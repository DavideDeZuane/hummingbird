import docker
import subprocess
import os
import glob
import time
import sys

from utils.log import *

""" We'll use this object to send command to the docker socket """
docker_client = docker.from_env()


def is_docker_running():
    """Check if Docker is running"""
    try:
        subprocess.run(["docker", "info"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        return True
    except subprocess.CalledProcessError:
        return False
    except FileNotFoundError:
        print("[!] Docker is not installed.")
        sys.exit(1)

def start_docker_linux():
    """Starting Docker onLinux"""
    print("[*] Starting Docker...")
    subprocess.run(["sudo", "systemctl", "start", "docker"], check=True)
    time.sleep(3)

def docker_compose_up(compose_file="docker-compose.yml"):
    subprocess.run(["docker-compose", "-f", compose_file, "up", "-d"], check=True)

def docker_compose_down(compose_file="docker-compose.yml"):
    subprocess.run(["docker-compose", "-f", compose_file, "down"], check=True)

def get_container_iflink(container_name: str) -> int:
    """
    veth ports exixts in pairs, we have one on the container side and the other on the host side
    Because of that we have two important id:
    - ifindex, the index of the interface
    - iflink, the index of the peer interface
    """
    # usually the interface inside a container is the eth0, so we have to find the corresponding veth in the host
    # to do that we see between the file of the device
    cmd = f"docker exec {container_name} cat /sys/class/net/eth0/iflink"
    try:
        iflink_str = subprocess.check_output(cmd, shell=True).decode().strip()
        return int(iflink_str)
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Error on reading interface inside the container: {e}")

def find_host_interface_by_ifindex(ifindex: int) -> str:
    """
    Now that we have the index of the interface on the host side we can find the ifname
    """
    for path in glob.glob("/sys/class/net/veth*/ifindex"):
        try:
            with open(path, "r") as f:
                current_index = int(f.read().strip())
                if current_index == ifindex:
                    return os.path.basename(os.path.dirname(path))
        except Exception:
            continue
    raise RuntimeError(f"Nessuna interfaccia host trovata con ifindex = {ifindex}")

def get_veth(container_name: str):
    try:
        iflink = get_container_iflink(container_name)
        host_ifname = find_host_interface_by_ifindex(iflink)
        return host_ifname;
    except Exception as e:
        log_err(f"Error: {e}")

def exec_in_container(container_name: str, command: str, workdir: str = None, privileged: bool = False) -> str:
    try:
        container = docker_client.containers.get(container_name)
        log_info(f"Running '{container_name}': {command}")

        result = container.exec_run(
            cmd=command,
            workdir=workdir,
            privileged=privileged,
            stdout=True,
            stderr=True,
            tty=False,
            stdin=False
        )

        output = result.output.decode("utf-8", errors="ignore").strip()
        print(output)
        if result.exit_code == 0:
            log_ok(f"Command inside '{container_name}' completed")
        else:
            log_err(f"Error running the command (exit code {result.exit_code})")

        return output

    except docker.errors.NotFound:
        log_err(f"Container '{container_name}' not found")
        raise
    except docker.errors.APIError as e:
        log_err(f"API Error: {e}")
        raise