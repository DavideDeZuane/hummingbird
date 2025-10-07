import docker
import subprocess
import os
import glob

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
        print(f"[!] Errore: {e}")

def print_container_info(container):
    info = container.attrs

    print("📦 Informazioni sul container:")
    print(f"  🔹 Nome: {info['Name'].strip('/')}")
    print(f"  🔹 ID: {container.short_id}")
    print(f"  🔹 Immagine: {info['Config']['Image']}")
    print(f"  🔹 Stato: {info['State']['Status']}")
    print(f"  🔹 PID: {info['State']['Pid']}")
    veth_name = get_veth(info['Name'.strip('/')])
    print(f"  🔹 Interfaccia veth lato host: {veth_name}")



if __name__ == "__main__":
    get_veth("moon");

