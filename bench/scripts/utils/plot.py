import matplotlib.pyplot as plt
import numpy as np
import statistics
from scipy.stats import norm

def plot_memory_distribution(memory_values, title="Distribuzione uso memoria", save_path=None):
    """
    Plotta la distribuzione dei valori di memoria e evidenzia media e deviazione standard.

    Args:
        memory_values (list[float]): Lista dei valori di memoria (es. memory_peak o memory_avg).
        title (str): Titolo del grafico.
        save_path (str): Path opzionale per salvare il grafico come file PNG.
    """
    mu = statistics.mean(memory_values)
    sigma = statistics.stdev(memory_values)

    # Genera asse X per curva di densità
    x = np.linspace(min(memory_values), max(memory_values), 200)
    pdf = norm.pdf(x, mu, sigma)  # distribuzione gaussiana teorica

    plt.figure(figsize=(8, 5))
    plt.title(title, fontsize=14, weight="bold")
    plt.xlabel("Memoria (MB)")
    plt.ylabel("Densità di probabilità")

    # Istogramma dei valori osservati
    plt.hist(memory_values, bins=10, density=True, alpha=0.6, color="#69b3a2", edgecolor="black", label="Valori osservati")

    # Curva gaussiana teorica
    plt.plot(x, pdf, color="darkblue", linewidth=2, label=f"Distribuzione N({mu:.2f}, {sigma:.2f}²)")

    # Linee verticali per media e deviazione standard
    plt.axvline(mu, color="red", linestyle="--", linewidth=2, label=f"Media: {mu:.2f} MB")
    plt.axvline(mu + sigma, color="orange", linestyle="--", linewidth=1.5, label=f"+1σ: {mu + sigma:.2f} MB")
    plt.axvline(mu - sigma, color="orange", linestyle="--", linewidth=1.5, label=f"-1σ: {mu - sigma:.2f} MB")

    # Evidenzia l'area ±1σ
    plt.fill_betweenx(np.linspace(0, max(pdf), 100), mu - sigma, mu + sigma, color="orange", alpha=0.15)

    plt.legend()
    plt.grid(alpha=0.3)

    if save_path:
        plt.tight_layout()
        plt.savefig(save_path, dpi=200)
        print(f"📈 Grafico salvato in {save_path}")
    else:
        plt.show()
