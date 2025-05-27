

#include <iostream>
#include <vector>
#include <chrono>
#include <algorithm>
#include <numeric> // Include necessary header for std::accumulate
#include <immintrin.h>
#include <execution>
#include <thread>
#include <future>


long long sum_loop(const std::vector<int>& numbers)
{
	long long sum = 0;
	for (long long i = 0; i < numbers.size(); ++i)
	{
		sum += numbers[i];
	}
	return sum;
}

// Fixing the error by replacing "std::accumu" with "std::accumulate" and completing the implementation of sum1 function.



long long sum_acc(const std::vector<int>& numbers)
{
	long long sum = 0;
	sum = std::accumulate(numbers.begin(), numbers.end(), 0LL); // Use std::accumulate to calculate the sum
	return sum;
}

long long sum_range_loop(const std::vector<int>& numbers) {
	long long sum = 0;
	for (int num : numbers) {
		sum += num;
	}
	return sum;
}

long long sum_unroll(const std::vector<int>& numbers) {
	long long sum = 0;
	size_t i = 0;
	size_t size = numbers.size();
	size_t limit = size - size % 4;

	for (; i < limit; i += 4) {
		sum += numbers[i] + numbers[i + 1] + numbers[i + 2] + numbers[i + 3];
	}

	for (; i < size; ++i) {
		sum += numbers[i];
	}

	return sum;
}

long long sum_simd(const std::vector<int>& numbers)
{
	const std::size_t n = numbers.size();
	const int* p = numbers.data();
	std::size_t       i = 0;

	__m256i acc_lo = _mm256_setzero_si256();   // 4 × int64
	__m256i acc_hi = _mm256_setzero_si256();   // 4 × int64

	constexpr std::size_t kStep = 8;           // 8 x int32 per loop

	for (; i + kStep <= n; i += kStep) {
		// load 8 x int32
		__m256i v = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(p + i));

		// split into low/high 128-bit halves
		__m128i lo128 = _mm256_castsi256_si128(v);
		__m128i hi128 = _mm256_extracti128_si256(v, 1);

		// sign-extend each half to 64-bit lanes
		__m256i lo64 = _mm256_cvtepi32_epi64(lo128);   // 4 × int64
		__m256i hi64 = _mm256_cvtepi32_epi64(hi128);   // 4 × int64

		// accumulate
		acc_lo = _mm256_add_epi64(acc_lo, lo64);
		acc_hi = _mm256_add_epi64(acc_hi, hi64);
	}

	// combine the two partial sums
	__m256i acc = _mm256_add_epi64(acc_lo, acc_hi);

	alignas(32) long long tmp[4];
	_mm256_store_si256(reinterpret_cast<__m256i*>(tmp), acc);

	long long sum = tmp[0] + tmp[1] + tmp[2] + tmp[3];

	// tail (n not multiple of 8)
	for (; i < n; ++i) sum += p[i];

	return sum;
}

long long sum_parallel(const std::vector<int>& numbers) {
	return std::reduce(std::execution::par_unseq, numbers.begin(), numbers.end(), 0LL);
}

long long sum_transform_reduce(const std::vector<int>& numbers) {
	return std::transform_reduce(
		std::execution::par_unseq,
		numbers.begin(), numbers.end(),
		0LL,
		std::plus<>(),  // Reduction operation
		[](int v) { return static_cast<long long>(v); }  // Unary transform operation
	);
}

long long sum_parallel_jthread(const std::vector<int>& numbers) {
	const size_t length = numbers.size();

	if (length == 0) return 0;

	const size_t num_threads = std::min(std::thread::hardware_concurrency(), static_cast<unsigned int>(length));
	const size_t chunk_size = length / num_threads;

	std::vector<long long> partial_sums(num_threads, 0);
	std::vector<std::jthread> threads;
	std::mutex mutex;

	auto worker = [&numbers, &partial_sums, &mutex](size_t start, size_t end, size_t index) {
		long long local_sum = std::accumulate(numbers.begin() + start, numbers.begin() + end, 0LL);
		//std::lock_guard<std::mutex> lock(mutex);
		partial_sums[index] = local_sum;
		};

	size_t chunk_start = 0;

	for (size_t i = 0; i < num_threads; ++i) {
		size_t chunk_end = (i == num_threads - 1) ? length : chunk_start + chunk_size;
		std::jthread worker_thread(worker, chunk_start, chunk_end, i);
		//threads.emplace_back(worker, chunk_start, chunk_end, i);
		chunk_start = chunk_end;
	}

	return std::accumulate(partial_sums.begin(), partial_sums.end(), 0LL);
}


long long sum_async_hw(const std::vector<int>& v)
{
	const size_t n = v.size();
	const size_t k = std::thread::hardware_concurrency();

	const size_t chunk = (n + k - 1) / k; // ceil division  
	std::vector<std::future<long long>> futs;
	futs.reserve(k);

	for (size_t i = 0; i < k; ++i) {
		size_t start = i * chunk;
		size_t end = std::min(start + chunk, n);
		if (start >= n) break; // Avoid out-of-bound chunks  

		futs.emplace_back(std::async(std::launch::async, [start, end, &v]() {
			return std::accumulate(v.begin() + start, v.begin() + end, 0LL);
			}));
	}

	long long total_sum = 0;
	for (auto& f : futs) {
		total_sum += f.get();
	}

	return total_sum;
}


void exec_and_print(const std::vector<int>& numbers, long long (*sum_func)(const std::vector<int>&))
{
	std::chrono::high_resolution_clock::time_point t1;
	std::chrono::high_resolution_clock::time_point t2;

	t1 = std::chrono::high_resolution_clock::now();
	long long result = sum_func(numbers);
	t2 = std::chrono::high_resolution_clock::now();
	auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1).count();
	std::cout << "Sum: " << result << "   in   " << duration << " milliseconds" << std::endl;
}



int main()
{
	std::vector<int> numbers(10'000'000'000, 3);

	std::cout << " sum_loop             : ";
	exec_and_print(numbers, sum_loop);

	std::cout << " sum_acc              : ";
	exec_and_print(numbers, sum_acc);

	std::cout << " sum_range_loop       : ";
	exec_and_print(numbers, sum_range_loop);

	std::cout << " sum_unroll           : ";
	exec_and_print(numbers, sum_unroll);

	std::cout << " sum_simd             : ";
	exec_and_print(numbers, sum_simd);

	std::cout << " sum_parallel         : ";
	exec_and_print(numbers, sum_parallel);

	std::cout << " sum_transform_reduce : ";
	exec_and_print(numbers, sum_transform_reduce);

	std::cout << " sum_parallel_jthread : ";
	exec_and_print(numbers, sum_parallel_jthread);

	std::cout << " sum_async_hw         : ";
	exec_and_print(numbers, sum_async_hw);

}


