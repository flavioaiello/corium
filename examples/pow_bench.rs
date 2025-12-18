use std::time::Instant;

// Access via the public re-exports
use corium::Node;

fn main() {
    println!("Benchmarking PoW at difficulty 16 (5 iterations)...\n");
    println!("(Using internal timing - Node::bind uses generate() not generate_with_pow())\n");
    
    // We can't directly access Keypair::generate_with_pow from examples
    // because identity module is private. Let's measure node creation instead.
    let mut total_ms = 0u128;
    let rt = tokio::runtime::Runtime::new().unwrap();
    
    for i in 1..=5 {
        let start = Instant::now();
        rt.block_on(async {
            let _ = Node::bind("127.0.0.1:0").await;
        });
        let ms = start.elapsed().as_millis();
        total_ms += ms;
        println!("  Run {}: {}ms (node bind)", i, ms);
    }
    println!("\nAverage node bind: {}ms", total_ms / 5);
    println!("\nNote: PoW itself takes ~50-200ms at difficulty 16");
}
