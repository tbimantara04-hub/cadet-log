import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

def main():
    user_counts = [50, 100]
    avg_latencies = [2.193, 5.728]
    max_latencies = [4.016, 8.277]

    plt.figure(figsize=(8, 5))
    plt.plot(user_counts, avg_latencies, marker='o', label='Rata-rata Latensi (s)')
    plt.plot(user_counts, max_latencies, marker='o', label='Latensi Maksimum (s)')
    for x, y in zip(user_counts, avg_latencies):
        plt.text(x, y + 0.14, f'{y:.3f}s', ha='center', va='bottom')
    for x, y in zip(user_counts, max_latencies):
        plt.text(x, y + 0.14, f'{y:.3f}s', ha='center', va='bottom')

    plt.title('Hasil Load Test FastAPI Backend')
    plt.xlabel('Jumlah Simulasi Pengguna')
    plt.ylabel('Waktu Latensi HTTP (detik)')
    plt.xticks(user_counts)
    plt.grid(True, linestyle='--', alpha=0.4)
    plt.legend()
    plt.tight_layout()
    output_path = 'backend/test_results_latency.png'
    plt.savefig(output_path, dpi=150)
    print(output_path)


if __name__ == '__main__':
    main()
