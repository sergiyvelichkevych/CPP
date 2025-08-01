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
#include <cstdint>

template<typename ValueType>
class Trie {
private:
    static constexpr size_t MAX_KEY_LENGTH = 64;
    
    struct TrieNode;
    using NodePtr = std::unique_ptr<TrieNode>;
    
    // Compact child storage - only store actually used characters
    struct CompactChildren {
        struct Child {
            char ch;
            NodePtr node;
            
            Child(char c, NodePtr n) : ch(c), node(std::move(n)) {}
        };
        
        std::vector<Child> children;
        
        // Find child by character (binary search)
        NodePtr* find(char c) {
            auto it = std::lower_bound(children.begin(), children.end(), c,
                [](const Child& child, char ch) { return child.ch < ch; });
            
            if (it != children.end() && it->ch == c) {
                return &it->node;
            }
            return nullptr;
        }
        
        // Insert or get child
        NodePtr& insert_or_get(char c) {
            auto it = std::lower_bound(children.begin(), children.end(), c,
                [](const Child& child, char ch) { return child.ch < ch; });
            
            if (it != children.end() && it->ch == c) {
                return it->node;
            }
            
            // Insert new child at correct position
            it = children.emplace(it, c, nullptr);
            return it->node;
        }
        
        // Remove child
        void remove(char c) {
            auto it = std::lower_bound(children.begin(), children.end(), c,
                [](const Child& child, char ch) { return child.ch < ch; });
            
            if (it != children.end() && it->ch == c) {
                children.erase(it);
            }
        }
        
        bool empty() const { return children.empty(); }
        size_t size() const { return children.size(); }
    };
    
    struct TrieNode {
        CompactChildren children;
        std::optional<uint32_t> value_index; // Use uint32_t to save memory
        
        TrieNode() = default;
    };
    
    NodePtr root;
    std::vector<ValueType> value_pool;
    std::vector<uint32_t> free_indices; // Reuse deleted value slots
    
    // Memory pool for nodes to reduce allocation overhead
    struct NodeAllocator {
        static constexpr size_t BLOCK_SIZE = 1024;
        
        struct Block {
            std::vector<TrieNode> nodes;
            size_t used = 0;
            
            Block() : nodes(BLOCK_SIZE) {}
        };
        
        std::vector<std::unique_ptr<Block>> blocks;
        std::vector<TrieNode*> free_nodes;
        
        TrieNode* allocate() {
            if (!free_nodes.empty()) {
                TrieNode* node = free_nodes.back();
                free_nodes.pop_back();
                new (node) TrieNode(); // Placement new
                return node;
            }
            
            if (blocks.empty() || blocks.back()->used >= BLOCK_SIZE) {
                blocks.push_back(std::make_unique<Block>());
            }
            
            Block* block = blocks.back().get();
            return &block->nodes[block->used++];
        }
        
        void deallocate(TrieNode* node) {
            node->~TrieNode(); // Explicit destructor call
            free_nodes.push_back(node);
        }
        
        void clear() {
            blocks.clear();
            free_nodes.clear();
        }
    };
    
    static NodeAllocator node_allocator;
    
    // Custom deleter for unique_ptr to use our allocator
    struct NodeDeleter {
        void operator()(TrieNode* node) const {
            if (node) {
                node_allocator.deallocate(node);
            }
        }
    };
    
    // Helper to make a node using our allocator
    static NodePtr make_node() {
        return NodePtr(node_allocator.allocate(), NodeDeleter{});
    }
    
    // Helper to validate key
    static void validate_key(std::string_view key) {
        if (key.empty() || key.length() > MAX_KEY_LENGTH) {
            throw std::invalid_argument("Key must be 1-64 characters long");
        }
    }
    
public:
    Trie() : root(make_node()) {
        value_pool.reserve(1024); // Pre-allocate for performance
    }
    
    ~Trie() {
        clear();
    }
    
    // Move constructor
    Trie(Trie&& other) noexcept 
        : root(std::move(other.root)),
          value_pool(std::move(other.value_pool)),
          free_indices(std::move(other.free_indices)) {
        other.root = make_node();
    }
    
    // Move assignment
    Trie& operator=(Trie&& other) noexcept {
        if (this != &other) {
            clear();
            root = std::move(other.root);
            value_pool = std::move(other.value_pool);
            free_indices = std::move(other.free_indices);
            other.root = make_node();
        }
        return *this;
    }
    
    // Delete copy operations
    Trie(const Trie&) = delete;
    Trie& operator=(const Trie&) = delete;
    
    // Insert or update key-value pair
    void insert(std::string_view key, ValueType value) {
        validate_key(key);
        
        TrieNode* current = root.get();
        
        for (char c : key) {
            NodePtr& child = current->children.insert_or_get(c);
            if (!child) {
                child = make_node();
            }
            current = child.get();
        }
        
        if (current->value_index.has_value()) {
            // Update existing value
            value_pool[current->value_index.value()] = std::move(value);
        } else {
            // Insert new value
            uint32_t new_index;
            if (!free_indices.empty()) {
                // Reuse a freed slot
                new_index = free_indices.back();
                free_indices.pop_back();
                value_pool[new_index] = std::move(value);
            } else {
                // Add to end of pool
                new_index = static_cast<uint32_t>(value_pool.size());
                if (new_index >= UINT32_MAX - 1) {
                    throw std::overflow_error("Value pool size exceeded");
                }
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
            NodePtr* child = current->children.find(c);
            if (!child || !*child) {
                return nullptr;
            }
            current = child->get();
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
        
        struct PathNode {
            TrieNode* node;
            char ch;
        };
        
        std::vector<PathNode> path;
        path.reserve(key.length() + 1);
        
        TrieNode* current = root.get();
        path.push_back({current, '\0'});
        
        // Find the node
        for (char c : key) {
            NodePtr* child = current->children.find(c);
            if (!child || !*child) {
                return false; // Key not found
            }
            current = child->get();
            path.push_back({current, c});
        }
        
        if (!current->value_index.has_value()) {
            return false; // Key not found
        }
        
        // Mark value slot as free
        free_indices.push_back(current->value_index.value());
        current->value_index.reset();
        
        // Clean up empty nodes
        for (size_t i = path.size() - 1; i > 0; --i) {
            TrieNode* node = path[i].node;
            
            if (node->children.empty() && !node->value_index.has_value()) {
                // Remove this node
                path[i - 1].node->children.remove(path[i].ch);
            } else {
                break; // Stop cleanup, node is still needed
            }
        }
        
        return true;
    }
    
    // Clear all entries
    void clear() {
        root = make_node();
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
        
        value_pool.shrink_to_fit();
    }
    
    // Get memory statistics
    struct MemoryStats {
        size_t node_count;
        size_t value_count;
        size_t free_slots;
        size_t child_entries;
        size_t approximate_bytes;
    };
    
    MemoryStats get_memory_stats() const {
        MemoryStats stats{};
        count_nodes(root.get(), stats.node_count, stats.child_entries);
        stats.value_count = value_pool.size();
        stats.free_slots = free_indices.size();
        
        // More accurate memory calculation
        stats.approximate_bytes = 
            stats.node_count * sizeof(TrieNode) +
            stats.child_entries * sizeof(CompactChildren::Child) +
            value_pool.capacity() * sizeof(ValueType) +
            free_indices.capacity() * sizeof(uint32_t) +
            node_allocator.blocks.size() * NodeAllocator::BLOCK_SIZE * sizeof(TrieNode);
            
        return stats;
    }
    
    // Static method to clear global allocator (call after all Tries are destroyed)
    static void clear_allocator() {
        node_allocator.clear();
    }
    
private:
    void count_nodes(const TrieNode* node, size_t& node_count, size_t& child_count) const {
        if (!node) return;
        node_count++;
        child_count += node->children.size();
        
        for (const auto& child : node->children.children) {
            count_nodes(child.node.get(), node_count, child_count);
        }
    }
};

// Define static member
template<typename ValueType>
typename Trie<ValueType>::NodeAllocator Trie<ValueType>::node_allocator;

#endif // TRIE_KV_STORAGE_HPP