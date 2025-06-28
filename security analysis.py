import matplotlib.pyplot as plt
import numpy as np

def simulate_4_level_cracking_times_with_n_fixed_keys():
    # Fixed key sizes for each algorithm (more realistic)
    aes_key_size = 256      # bits - AES-256
    twofish_key_size = 256  # bits - Twofish-256  
    chacha20_key_size = 256 # bits - ChaCha20 (always 256)
    
    # Changed to multiples of 8 as requested
    n_values = [8, 16, 24, 32, 48, 64, 96, 128, 192, 256]  # bytes, multiples of 8
    results = {
        'n_values': n_values,
        'aes_key_size': aes_key_size,
        'twofish_key_size': twofish_key_size,
        'chacha20_key_size': chacha20_key_size,
        'detailed_results': {
            'aes_cracking_times': [],
            'twofish_cracking_times': [],
            'chacha20_cracking_times': [],
            'n_cracking_times': [],
            'total_cracking_times': []
        }
    }
    
    for n in n_values:
        # AES cracking time (CONSTANT - fixed key size, unaffected by n)
        aes_time = 10 ** (aes_key_size / 100)
        
        # Twofish cracking time (CONSTANT - fixed key size, n doesn't affect cracking difficulty)
        # Note: n affects key reconstruction, not brute force difficulty
        twofish_time = 10 ** (twofish_key_size / 100) * 1.2
        
        # ChaCha20 cracking time (CONSTANT - always 256-bit security)
        chacha20_time = 10 ** (chacha20_key_size / 100)
        
        # FIXED: n-parameter cracking time (VARIES - represents difficulty of guessing n)
        # Removed the min() cap to allow continuous growth
        # Using logarithmic scaling to keep values reasonable but still growing
        n_cracking_time = 10 ** (n * 0.05)  # Scales more gradually with n, no cap
        
        # Total cracking time (VARIES - coordination gets harder with larger n)
        # Larger n means more complex key reconstruction
        coordination_factor = 1.2 + (n / 200)  # Increases with n
        total_time = max(aes_time, twofish_time, chacha20_time) * coordination_factor
        
        results['detailed_results']['aes_cracking_times'].append(aes_time)
        results['detailed_results']['twofish_cracking_times'].append(twofish_time)
        results['detailed_results']['chacha20_cracking_times'].append(chacha20_time)
        results['detailed_results']['n_cracking_times'].append(n_cracking_time)
        results['detailed_results']['total_cracking_times'].append(total_time)
    
    return results

def simulate_varying_key_sizes_fixed_n():
    """New function: Fixed n, varying key sizes"""
    key_sizes = [128, 192, 256, 384, 512, 768, 1024]  # bits
    n_fixed = 32  # bytes (fixed)
    
    results = {
        'key_sizes': key_sizes,
        'n_fixed': n_fixed,
        'detailed_results': {
            'aes_cracking_times': [],
            'twofish_cracking_times': [],
            'chacha20_cracking_times': [],
            'n_cracking_times': [],
            'total_cracking_times': []
        }
    }
    
    # n cracking time (CONSTANT - n is fixed)
    n_cracking_time_constant = 10 ** (n_fixed * 0.05)  # Updated to match new formula
    
    for key_size in key_sizes:
        # AES cracking time (INCREASES with key size)
        aes_time = 10 ** (key_size / 100)
        
        # Twofish cracking time (INCREASES with key size)
        twofish_time = 10 ** (key_size / 100) * 1.2
        
        # ChaCha20 cracking time (INCREASES with key size - now varies!)
        chacha20_time = 10 ** (key_size / 100) * 1.1
        
        # n cracking time (CONSTANT - n is fixed)
        n_cracking_time = n_cracking_time_constant
        
        # Total security (maximum of all layers)
        coordination_factor = 1.5
        total_time = max(aes_time, twofish_time, chacha20_time) * coordination_factor
        
        results['detailed_results']['aes_cracking_times'].append(aes_time)
        results['detailed_results']['twofish_cracking_times'].append(twofish_time)
        results['detailed_results']['chacha20_cracking_times'].append(chacha20_time)
        results['detailed_results']['n_cracking_times'].append(n_cracking_time)
        results['detailed_results']['total_cracking_times'].append(total_time)
    
    return results

def create_improved_security_graphs(results):
    # Clear any existing plots
    plt.clf()
    plt.close('all')
    
    # Set up matplotlib parameters
    plt.rcParams['figure.figsize'] = (18, 6)
    plt.rcParams['font.size'] = 11
    
    # Create subplot layout with only 3 graphs (removing the effective key strength graph)
    fig, (ax1, ax2, ax3) = plt.subplots(1, 3, figsize=(18, 6))
    
    # Graph 1: All security layers vs n parameter (FIXED!)
    security_layers = {
        'AES-256': results['detailed_results']['aes_cracking_times'],
        'Twofish-256': results['detailed_results']['twofish_cracking_times'],
        'ChaCha20-256': results['detailed_results']['chacha20_cracking_times'],
        'n-parameter': results['detailed_results']['n_cracking_times'],
        'Total Cracking Time': results['detailed_results']['total_cracking_times']
    }
    
    colors = ['blue', 'red', 'green', 'orange', 'black']
    linestyles = ['-', '--', '-.', ':', '-']
    markers = ['o', 's', '^', 'd', 'x']
    linewidths = [2, 2, 2, 2, 3]  # Make total line thicker
    
    for i, (layer, times) in enumerate(security_layers.items()):
        ax1.plot(results['n_values'], times, 
                color=colors[i], linestyle=linestyles[i], marker=markers[i],
                linewidth=linewidths[i], label=layer, markersize=7)
    
    ax1.set_xlabel('n Parameter (bytes)', fontweight='bold')
    ax1.set_ylabel('Cracking Time (seconds)', fontweight='bold')
    ax1.set_title('Security Analysis: Fixed Key Sizes vs n Parameter', fontweight='bold')
    ax1.legend(fontsize=10)
    ax1.grid(True, alpha=0.3)
    ax1.set_yscale('log')
    
    # FIXED: Ensure x-axis shows all n values clearly
    ax1.set_xticks(results['n_values'])
    ax1.set_xticklabels(results['n_values'])
    
    # Graph 2: Security breakdown with better visibility
    width = 0.15
    x = np.arange(len(results['n_values']))
    
    # Create grouped bar chart for better visibility
    bars1 = ax2.bar(x - 1.5*width, results['detailed_results']['aes_cracking_times'], 
                   width, label='AES-256', color='blue', alpha=0.8)
    bars2 = ax2.bar(x - 0.5*width, results['detailed_results']['twofish_cracking_times'], 
                   width, label='Twofish-256', color='red', alpha=0.8)
    bars3 = ax2.bar(x + 0.5*width, results['detailed_results']['chacha20_cracking_times'], 
                   width, label='ChaCha20-256', color='green', alpha=0.8)
    bars4 = ax2.bar(x + 1.5*width, results['detailed_results']['n_cracking_times'], 
                   width, label='n-parameter', color='orange', alpha=0.8)
    
    ax2.set_xlabel('n Parameter (bytes)', fontweight='bold')
    ax2.set_ylabel('Cracking Time (seconds)', fontweight='bold')
    ax2.set_title('Individual Security Layers (Bar Chart)', fontweight='bold')
    ax2.set_xticks(x)
    ax2.set_xticklabels(results['n_values'])
    ax2.legend()
    ax2.set_yscale('log')
    ax2.grid(True, alpha=0.3, axis='y')
    
    # Graph 3: Varying key sizes with fixed n
    results_varying = simulate_varying_key_sizes_fixed_n()
    
    security_layers_varying = {
        'AES (varying)': results_varying['detailed_results']['aes_cracking_times'],
        'Twofish (varying)': results_varying['detailed_results']['twofish_cracking_times'],
        'ChaCha20 (varying)': results_varying['detailed_results']['chacha20_cracking_times'],
        'n (constant)': results_varying['detailed_results']['n_cracking_times'],
        'Total Cracking Time': results_varying['detailed_results']['total_cracking_times']
    }
    
    colors_varying = ['blue', 'red', 'green', 'orange', 'black']
    linestyles_varying = ['-', '--', '-.', ':', '-']
    markers_varying = ['o', 's', '^', 'd', 'x']
    linewidths_varying = [2, 2, 2, 2, 3]
    
    for i, (layer, times) in enumerate(security_layers_varying.items()):
        ax3.plot(results_varying['key_sizes'], times, 
                color=colors_varying[i], linestyle=linestyles_varying[i], marker=markers_varying[i],
                linewidth=linewidths_varying[i], label=layer, markersize=7)
    
    ax3.set_xlabel('Key Size (bits)', fontweight='bold')
    ax3.set_ylabel('Cracking Time (seconds)', fontweight='bold')
    ax3.set_title(f'Security vs Key Size (n = {results_varying["n_fixed"]} bytes fixed)', fontweight='bold')
    ax3.legend(fontsize=10)
    ax3.grid(True, alpha=0.3)
    ax3.set_xscale('log', base=2)
    ax3.set_yscale('log')
    
    plt.tight_layout()
    
    # Save the figure
    try:
        plt.savefig('improved_3_graph_security_analysis.png', dpi=300, bbox_inches='tight')
        print("✓ Graph saved as: improved_3_graph_security_analysis.png")
    except Exception as e:
        print(f"✗ Error saving graph: {e}")
    
    # Display the figure
    try:
        plt.show()
        print("✓ Graphs displayed successfully")
    except Exception as e:
        print(f"✗ Error displaying graphs: {e}")
        print("  Note: Graphs were still saved to file")

def analyze_optimal_n_fixed_keys(results):
    """Analyze optimal n values with fixed key sizes"""
    print("\n=== n Parameter Analysis (Fixed Key Sizes) ===")
    print(f"AES: {results['aes_key_size']} bits (constant)")
    print(f"Twofish: {results['twofish_key_size']} bits (constant)")
    print(f"ChaCha20: {results['chacha20_key_size']} bits (constant)")
    
    print(f"\n{'n (bytes)':<10} {'AES':<12} {'Twofish':<12} {'ChaCha20':<12} {'n-param':<12} {'Total':<12}")
    print("-" * 75)
    
    best_n = None
    best_total_time = 0
    
    for i, n in enumerate(results['n_values']):
        aes_time = results['detailed_results']['aes_cracking_times'][i]
        twofish_time = results['detailed_results']['twofish_cracking_times'][i]
        chacha20_time = results['detailed_results']['chacha20_cracking_times'][i]
        n_time = results['detailed_results']['n_cracking_times'][i]
        total_time = results['detailed_results']['total_cracking_times'][i]
        
        if total_time > best_total_time:
            best_total_time = total_time
            best_n = n
        
        print(f"{n:<10} {aes_time:<12.2e} {twofish_time:<12.2e} {chacha20_time:<12.2e} {n_time:<12.2e} {total_time:<12.2e}")
    
    print(f"\n→ Optimal n: {best_n} bytes (highest total cracking time)")

def main():
    print("Starting 3-Graph Security Analysis...")
    print("Using fixed key sizes: AES-256, Twofish-256, ChaCha20-256")
    print("Analyzing impact of n parameter on security layers...")
    print("n values are multiples of 8: [8, 16, 24, 32, 48, 64, 96, 128, 192, 256]")
    
    results = simulate_4_level_cracking_times_with_n_fixed_keys()
    
    print("\nGenerating 3 security graphs...")
    create_improved_security_graphs(results)
    
    analyze_optimal_n_fixed_keys(results)
    
    print("\n=== Key Insights ===")
    print("GRAPH 1 (Fixed key sizes, varying n):")
    print("  • AES, Twofish, ChaCha20 lines: CONSTANT (fixed key sizes)")
    print("  • n parameter line: INCREASES continuously (varies with n)")
    print("  • Total cracking time: INCREASES (complexity grows with n)")
    print("\nGRAPH 2 (Individual security layers - bar chart):")
    print("  • Shows the same data as Graph 1 but in bar chart format")
    print("  • Better visibility for comparing individual layer contributions")
    print("\nGRAPH 3 (Varying key sizes, fixed n):")
    print("  • AES, Twofish, ChaCha20 lines: INCREASE (larger keys = harder to crack)")
    print("  • n parameter line: CONSTANT (fixed n = 32 bytes)")
    print("  • Total cracking time: INCREASES (follows strongest algorithm)")
    
    print("\nGraph saved: improved_3_graph_security_analysis.png")

if __name__ == "__main__":
    try:
        import matplotlib
        # Try to set a backend that works
        try:
            matplotlib.use('TkAgg')
        except:
            try:
                matplotlib.use('Qt5Agg')
            except:
                try:
                    matplotlib.use('Agg')  # Non-interactive backend as fallback
                    print("Warning: Using non-interactive backend. Graphs will be saved but may not display.")
                except:
                    pass
        
        import matplotlib.pyplot as plt
        import numpy as np
        
        print("✓ Successfully imported matplotlib and numpy")
        
    except ImportError as e:
        print("✗ Please install required packages:")
        print("pip install matplotlib numpy")
        print(f"Error: {e}")
        exit(1)
    
    main()
    
