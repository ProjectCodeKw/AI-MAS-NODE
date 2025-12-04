
from llama_cpp import Llama
import time
import psutil
import statistics
from datetime import datetime

class ModelBenchmark:
    def __init__(self, model_path: str):
        self.model_path = model_path
        self.llm = None
        self.benchmark_results = {
            "load_time": 0,
            "memory_before": 0,
            "memory_after": 0,
            "prompt_times": [],
            "token_speeds": [],
            "test_results": []
        }
    
    def print_header(self, title: str):
        print("\n" + "="*60)
        print(f"  {title}")
        print("="*60)
    
    def run_benchmark(self):
        """Run complete benchmark suite"""
        print(f"=== TinyLlama Benchmark Test ===")
        print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Model: {self.model_path}")
        
        # Phase 1: System Check
        self.print_header("PHASE 1: SYSTEM CHECK")
        self.check_system()
        
        # Phase 2: Model Loading Benchmark
        self.print_header("PHASE 2: MODEL LOADING")
        self.load_model()
        
        # Phase 3: Prompt Performance Benchmark
        self.print_header("PHASE 3: PROMPT PERFORMANCE")
        self.run_prompt_benchmarks()
        
        # Phase 4: Memory Analysis
        self.print_header("PHASE 4: MEMORY ANALYSIS")
        self.analyze_memory()
        
        # Phase 5: Summary Report
        self.print_header("BENCHMARK SUMMARY")
        self.print_summary()
    
    def check_system(self):
        """Check system resources"""
        cpu_count = psutil.cpu_count()
        cpu_freq = psutil.cpu_freq()
        mem = psutil.virtual_memory()
        swap = psutil.swap_memory()
        
        print(f"CPU Cores: {cpu_count}")
        if cpu_freq:
            print(f"CPU Frequency: {cpu_freq.current:.0f} MHz")
        print(f"Total RAM: {mem.total / (1024**3):.2f} GB")
        print(f"Available RAM: {mem.available / (1024**3):.2f} GB")
        print(f"RAM Used: {mem.percent}%")
        print(f"Swap Total: {swap.total / (1024**3):.2f} GB")
        print(f"Swap Used: {swap.percent}%")
        
        self.benchmark_results["memory_before"] = mem.available / (1024**3)
    
    def load_model(self):
        """Benchmark model loading time"""
        print("Loading model...")
        
        load_start = time.perf_counter()
        
        self.llm = Llama(
            model_path=self.model_path,
            n_ctx=1024,           # Context window
            n_threads=4,          # Use available cores
            n_batch=512,          # Reasonable batch size
            n_gpu_layers=0,
            verbose=False,
            use_mmap=True,
            use_mlock=False
        )
        
        load_end = time.perf_counter()
        load_time = load_end - load_start
        
        self.benchmark_results["load_time"] = load_time
        print(f"Model loaded in {load_time:.3f} seconds")
        
        # Check model info
        print(f"Context size: {self.llm.n_ctx()} tokens")
        print(f"Threads: {self.llm.n_threads}")
    
    def run_prompt_benchmarks(self):
        """Run multiple prompt benchmarks"""
        test_prompts = [
            {
                "name": "Simple Function",
                "prompt": "Write a Python function to calculate factorial of a number",
                "max_tokens": 100,
                "temperature": 0.1
            },
            {
                "name": "Medium Algorithm", 
                "prompt": "Create a function to check if a string is a palindrome in Python",
                "max_tokens": 150,
                "temperature": 0.2
            },
            {
                "name": "Complex Task",
                "prompt": "Write a Python class for a simple bank account with deposit, withdraw, and balance methods",
                "max_tokens": 200,
                "temperature": 0.3
            },
            {
                "name": "JavaScript Example",
                "prompt": "Create a JavaScript function to validate an email address using regex",
                "max_tokens": 120,
                "temperature": 0.2
            }
        ]
        
        for i, test in enumerate(test_prompts):
            print(f"\nTest {i+1}: {test['name']}")
            print(f"Prompt: {test['prompt']}")
            
            # Format for TinyLlama
            formatted_prompt = f"<|system|>\nYou are a coding assistant.</s>\n<|user|>\n{test['prompt']}</s>\n<|assistant|>\n"
            
            # Time the generation
            gen_start = time.perf_counter()
            
            response = self.llm(
                formatted_prompt,
                max_tokens=test['max_tokens'],
                temperature=test['temperature'],
                stop=["</s>", "<|"],
                echo=False
            )
            
            gen_end = time.perf_counter()
            gen_time = gen_end - gen_start
            
            # Get results
            generated_text = response['choices'][0]['text']
            token_count = len(self.llm.tokenize(generated_text.encode()))
            
            # Calculate metrics
            tokens_per_second = token_count / gen_time if gen_time > 0 else 0
            
            # Store results
            self.benchmark_results["prompt_times"].append(gen_time)
            self.benchmark_results["token_speeds"].append(tokens_per_second)
            
            test_result = {
                "name": test['name'],
                "time": gen_time,
                "tokens": token_count,
                "tokens_per_second": tokens_per_second,
                "output_preview": generated_text[:100] + "..." if len(generated_text) > 100 else generated_text
            }
            self.benchmark_results["test_results"].append(test_result)
            
            print(f"  Time: {gen_time:.3f}s")
            print(f"  Tokens: {token_count}")
            print(f"  Speed: {tokens_per_second:.1f} tokens/sec")
            print(f"  Output: {test_result['output_preview']}")
    
    def analyze_memory(self):
        """Analyze memory usage after tests"""
        mem = psutil.virtual_memory()
        swap = psutil.swap_memory()
        
        self.benchmark_results["memory_after"] = mem.available / (1024**3)
        
        print("Memory Usage After Tests:")
        print(f"  RAM Available: {mem.available / (1024**3):.2f} GB")
        print(f"  RAM Used: {mem.percent}%")
        print(f"  Swap Used: {swap.percent}%")
        
        memory_used = self.benchmark_results["memory_before"] - self.benchmark_results["memory_after"]
        print(f"  Memory Delta: {memory_used:.2f} GB")
    
    def print_summary(self):
        """Print comprehensive benchmark summary"""
        print("PERFORMANCE SUMMARY:")
        print("-" * 40)
        
        # Load time
        print(f"Model Load Time: {self.benchmark_results['load_time']:.3f} seconds")
        
        # Prompt statistics
        if self.benchmark_results["prompt_times"]:
            avg_time = statistics.mean(self.benchmark_results["prompt_times"])
            min_time = min(self.benchmark_results["prompt_times"])
            max_time = max(self.benchmark_results["prompt_times"])
            
            print(f"\nPrompt Generation:")
            print(f"  Average Time: {avg_time:.3f}s")
            print(f"  Best Time: {min_time:.3f}s")
            print(f"  Worst Time: {max_time:.3f}s")
        
        # Token speed statistics
        if self.benchmark_results["token_speeds"]:
            avg_speed = statistics.mean(self.benchmark_results["token_speeds"])
            min_speed = min(self.benchmark_results["token_speeds"])
            max_speed = max(self.benchmark_results["token_speeds"])
            
            print(f"\nToken Generation Speed:")
            print(f"  Average: {avg_speed:.1f} tokens/sec")
            print(f"  Best: {max_speed:.1f} tokens/sec")
            print(f"  Worst: {min_speed:.1f} tokens/sec")
        
        # Memory
        print(f"\nMemory Usage:")
        print(f"  Start: {self.benchmark_results['memory_before']:.2f} GB available")
        print(f"  End: {self.benchmark_results['memory_after']:.2f} GB available")
        
        # Overall rating
        print("\n" + "="*60)
        print("BENCHMARK COMPLETE")
        
        # Simple performance rating
        if self.benchmark_results["token_speeds"]:
            avg_speed = statistics.mean(self.benchmark_results["token_speeds"])
            if avg_speed > 20:
                rating = "EXCELLENT"
            elif avg_speed > 10:
                rating = "GOOD"
            elif avg_speed > 5:
                rating = "FAIR"
            else:
                rating = "SLOW"
            
            print(f"Overall Rating: {rating} ({avg_speed:.1f} tokens/sec)")

def main():
    # Model path
    model_path = "tinyllama-1.1b-chat-v1.0.Q4_0.gguf"
    
    # Run benchmark
    benchmark = ModelBenchmark(model_path)
    benchmark.run_benchmark()

if __name__ == "__main__":
    main()
