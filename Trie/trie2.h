#ifndef TRIE_KV_STORAGE_HPP
#define TRIE_KV_STORAGE_HPP

#include <memory>
#include <vector>
#include <string>
#include <string_view>
#include <optional>
#include <algorithm>
#include <stdexcept>
#include <utility>

template<typename ValueType>
class Trie {
private:
    static constexpr size_t ALPHABET_SIZE = 128; // ASCII characters
    static constexpr size_t MAX_KEY_LENGTH = 64;
    
    struct TrieNode {
        // Using array for children - faster than unordered_map for ASCII
        std::unique_ptr<TrieNode> children[ALPHABET_SIZE];
        std::optional<size_t> value_index; // Index into value pool
        
        TrieNode() = default;
        
        // Move constructor and assignment
        TrieNode(TrieNode&&) = default;
        TrieNode& operator=(TrieNode&&) = default;
        
        // Delete copy operations
        TrieNode(const TrieNode&) = delete;
        TrieNode& operator=(const TrieNode&) = delete;
    };
    
    std::unique_ptr<TrieNode> root;
    std::vector<ValueType> value_pool;
    std::vector<size_t> free_indices; // Reuse deleted value slots
    
    // Helper to validate key
    static void validate_key(std::string_view key) {
        if (key.empty() || key.length() > MAX_KEY_LENGTH) {
            throw std::invalid_argument("Key must be 1-64 characters long");
        }
        for (char c : key) {
            if (static_cast<unsigned char>(c) >= ALPHABET_SIZE) {
                throw std::invalid_argument("Key contains invalid character");
            }
        }
    }
    
public:
    Trie() : root(std::make_unique<TrieNode>()) {
        value_pool.reserve(1024); // Pre-allocate for performance
    }
    
    // Insert or update key-value pair
    void insert(std::string_view key, ValueType value) {
        validate_key(key);
        
        TrieNode* current = root.get();
        
        for (char c : key) {
            size_t index = static_cast<unsigned char>(c);
            if (!current->children[index]) {
                current->children[index] = std::make_unique<TrieNode>();
            }
            current = current->children[index].get();
        }
        
        if (current->value_index.has_value()) {
            // Update existing value
            value_pool[current->value_index.value()] = std::move(value);
        } else {
            // Insert new value
            size_t new_index;
            if (!free_indices.empty()) {
                // Reuse a freed slot
                new_index = free_indices.back();
                free_indices.pop_back();
                value_pool[new_index] = std::move(value);
            } else {
                // Add to end of pool
                new_index = value_pool.size();
                value_pool.push_back(std::move(value));
            }
            current->value_index = new_index;
        }
    }
    
    // Search for a key and return pointer to value (nullptr if not found)
    ValueType* find(std::string_view key) {
        validate_key(key);
        
        TrieNode* current = root.get();
        
        for (char c : key) {
            size_t index = static_cast<unsigned char>(c);
            if (!current->children[index]) {
                return nullptr;
            }
            current = current->children[index].get();
        }
        
        if (current->value_index.has_value()) {
            return &value_pool[current->value_index.value()];
        }
        return nullptr;
    }
    
    // Const version of find
    const ValueType* find(std::string_view key) const {
        return const_cast<Trie*>(this)->find(key);
    }
    
    // Check if key exists
    bool contains(std::string_view key) const {
        return find(key) != nullptr;
    }
    
    // Remove a key-value pair
    bool erase(std::string_view key) {
        validate_key(key);
        
        std::vector<TrieNode*> path;
        path.reserve(key.length() + 1);
        
        TrieNode* current = root.get();
        path.push_back(current);
        
        // Find the node
        for (char c : key) {
            size_t index = static_cast<unsigned char>(c);
            if (!current->children[index]) {
                return false; // Key not found
            }
            current = current->children[index].get();
            path.push_back(current);
        }
        
        if (!current->value_index.has_value()) {
            return false; // Key not found
        }
        
        // Mark value slot as free
        free_indices.push_back(current->value_index.value());
        current->value_index.reset();
        
        // Clean up empty nodes
        for (size_t i = path.size() - 1; i > 0; --i) {
            TrieNode* node = path[i];
            
            // Check if node has any children or value
            bool has_children = false;
            for (const auto& child : node->children) {
                if (child) {
                    has_children = true;
                    break;
                }
            }
            
            if (!has_children && !node->value_index.has_value()) {
                // Remove this node
                char c = key[i - 1];
                size_t index = static_cast<unsigned char>(c);
                path[i - 1]->children[index].reset();
            } else {
                break; // Stop cleanup, node is still needed
            }
        }
        
        return true;
    }
    
    // Clear all entries
    void clear() {
        root = std::make_unique<TrieNode>();
        value_pool.clear();
        free_indices.clear();
    }
    
    // Get number of key-value pairs
    size_t size() const {
        return value_pool.size() - free_indices.size();
    }
    
    // Check if empty
    bool empty() const {
        return size() == 0;
    }
    
    // Operator[] for convenient access (creates if doesn't exist)
    ValueType& operator[](std::string_view key) {
        ValueType* ptr = find(key);
        if (ptr) {
            return *ptr;
        }
        
        // Insert default value and return reference
        insert(key, ValueType{});
        return *find(key);
    }
    
    // Memory optimization: compact the value pool
    void compact() {
        if (free_indices.empty()) return;
        
        // Sort free indices in descending order
        std::sort(free_indices.rbegin(), free_indices.rend());
        
        // Remove freed values from the end
        while (!free_indices.empty() && free_indices.back() == value_pool.size() - 1) {
            value_pool.pop_back();
            free_indices.pop_back();
        }
        
        // Could implement more sophisticated compaction if needed
    }
    
    // Get memory statistics
    struct MemoryStats {
        size_t node_count;
        size_t value_count;
        size_t free_slots;
        size_t approximate_bytes;
    };
    
    MemoryStats get_memory_stats() const {
        MemoryStats stats{};
        count_nodes(root.get(), stats.node_count);
        stats.value_count = value_pool.size();
        stats.free_slots = free_indices.size();
        
        // Approximate memory usage
        stats.approximate_bytes = 
            stats.node_count * sizeof(TrieNode) +
            stats.value_count * sizeof(ValueType) +
            free_indices.capacity() * sizeof(size_t);
            
        return stats;
    }
    
private:
    void count_nodes(const TrieNode* node, size_t& count) const {
        if (!node) return;
        count++;
        for (const auto& child : node->children) {
            if (child) {
                count_nodes(child.get(), count);
            }
        }
    }
};

#endif // TRIE_KV_STORAGE_HPP