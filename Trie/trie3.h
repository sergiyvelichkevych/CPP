// compact_radix_trie.hpp  ────────────────────────────────────────────────
// Public‑domain / 0‑BSD  –  do what you like with it.
#pragma once
#include <vector>
#include <string>
#include <cstdint>
#include <limits>
#include <iostream>

template <class Value,
          std::size_t MAX_KEY_LEN = 64>         // compile‑time guard
class CompactRadixTrie {
    //───────────────────────────────────────────────────────────────────
    // 1.  Internal storage types
    //───────────────────────────────────────────────────────────────────
    struct Edge {
        char      ch;           // byte that labels this edge
        uint32_t  child;        // index in nodes_
        uint32_t  next;         // sibling edge, 0 = end of list

        Edge(char c = 0, uint32_t child_ = 0, uint32_t next_ = 0)
            : ch(c), child(child_), next(next_) {}
    };

    struct Node {
        uint32_t firstEdge = 0;                           // head of singly‑linked edge list
        uint32_t valIndex  = std::numeric_limits<uint32_t>::max(); // npos → no value
    };

    // pools – index 0 in edges_ is a dummy sentinel so “0” means “null”
    std::vector<Node>  nodes_{ { /* root node */ } };
    std::vector<Edge>  edges_{ { } };
    std::vector<Value> vals_;

    static constexpr uint32_t npos32 = std::numeric_limits<uint32_t>::max();

    //───────────────────────────────────────────────────────────────────
    // 2.  Helpers
    //───────────────────────────────────────────────────────────────────
    uint32_t new_node() {
        nodes_.emplace_back();
        return static_cast<uint32_t>(nodes_.size() - 1);
    }
    uint32_t new_edge(char c, uint32_t child, uint32_t next) {
        edges_.emplace_back(c, child, next);
        return static_cast<uint32_t>(edges_.size() - 1);
    }

    // Find edge carrying character *c* among the siblings that start at edgeIdx.
    // Returns {edgeIdx, prevIdx}.  If not found, edgeIdx == 0.
    struct EdgeSearch { uint32_t edge; uint32_t prev; };
    EdgeSearch find_edge(uint32_t first, char c) const {
        uint32_t prev = 0, cur = first;
        while (cur) {
            if (edges_[cur].ch == c) break;
            prev = cur;
            cur  = edges_[cur].next;
        }
        return { cur, prev };
    }

public:
    //───────────────────────────────────────────────────────────────────
    // 3.  Public API
    //───────────────────────────────────────────────────────────────────
    /// \returns true if a new key was added, false if the key already existed (value is updated).
    bool insert(const std::string& key, const Value& value) {
        if (key.size() > MAX_KEY_LEN) return false;       // guard

        uint32_t nodeIdx = 0;                             // start at root
        for (unsigned char uc : key) {
            char c = static_cast<char>(uc);
            auto [edgeIdx, prevIdx] = find_edge(nodes_[nodeIdx].firstEdge, c);

            // Edge exists → follow it.
            if (edgeIdx) { nodeIdx = edges_[edgeIdx].child; continue; }

            // No edge → create new edge + new node.
            uint32_t newNode = new_node();
            uint32_t newEdge = new_edge(c, newNode, 0);

            if (prevIdx)  edges_[prevIdx].next  = newEdge;
            else          nodes_[nodeIdx].firstEdge = newEdge;

            nodeIdx = newNode;
        }

        Node& n = nodes_[nodeIdx];
        bool existed = n.valIndex != npos32;

        if (existed) vals_[n.valIndex] = value;           // overwrite
        else {
            n.valIndex = static_cast<uint32_t>(vals_.size());
            vals_.push_back(value);
        }
        return !existed;
    }

    /// \returns pointer to the stored value or nullptr if key is absent.
    const Value* find(const std::string& key) const {
        if (key.size() > MAX_KEY_LEN) return nullptr;

        uint32_t nodeIdx = 0;
        for (unsigned char uc : key) {
            char c = static_cast<char>(uc);
            auto [edgeIdx, _] = find_edge(nodes_[nodeIdx].firstEdge, c);
            if (!edgeIdx) return nullptr;
            nodeIdx = edges_[edgeIdx].child;
        }
        const Node& n = nodes_[nodeIdx];
        return n.valIndex == npos32 ? nullptr : &vals_[n.valIndex];
    }

    /// \returns true if key existed and was erased.
    bool erase(const std::string& key) {
        if (key.size() > MAX_KEY_LEN) return false;

        // We keep a stack to backtrack for edge pruning.
        struct Frame { uint32_t node, prevEdge, edge; };
        Frame stack[MAX_KEY_LEN + 1];
        int   depth = 0;

        uint32_t nodeIdx = 0;
        for (unsigned char uc : key) {
            char c = static_cast<char>(uc);
            auto se = find_edge(nodes_[nodeIdx].firstEdge, c);
            if (!se.edge) return false;                   // key absent
            stack[depth++] = { nodeIdx, se.prev, se.edge };
            nodeIdx = edges_[se.edge].child;
        }

        Node& n = nodes_[nodeIdx];
        if (n.valIndex == npos32) return false;           // key absent
        n.valIndex = npos32;                              // logically delete

        // Optional: prune nodes that became unreachable
        while (depth--) {
            auto [parent, prevEdge, edge] = stack[depth];
            uint32_t child = edges_[edge].child;

            if (nodes_[child].firstEdge || nodes_[child].valIndex != npos32)
                break;                                    // child still needed

            // Unlink edge
            if (prevEdge) edges_[prevEdge].next = edges_[edge].next;
            else          nodes_[parent].firstEdge = edges_[edge].next;
        }
        return true;
    }

    //───────────────────────────────────────────────────────────────────
    // 4.  Memory statistics
    //───────────────────────────────────────────────────────────────────
    struct MemUsage {
        std::size_t node_bytes, edge_bytes, value_bytes;
        std::size_t total() const { return node_bytes + edge_bytes + value_bytes; }
    };

    MemUsage memory_used() const {
        return { nodes_.size() * sizeof(Node),
                 edges_.size() * sizeof(Edge),
                 vals_.size()  * sizeof(Value) };
    }
    MemUsage memory_reserved() const {
        return { nodes_.capacity() * sizeof(Node),
                 edges_.capacity() * sizeof(Edge),
                 vals_.capacity()  * sizeof(Value) };
    }

    std::size_t key_count()   const { return vals_.size(); }
    std::size_t node_count()  const { return nodes_.size(); }
    std::size_t edge_count()  const { return edges_.size() ? edges_.size() - 1 : 0; } // minus dummy
};

//─────────────────────────────────────────────────────────────────────────
// 5.  Tiny demonstration / smoke test
//─────────────────────────────────────────────────────────────────────────
#ifdef COMPACT_TRIE_DEMO
int main() {
    CompactRadixTrie<std::uint32_t> trie;

    trie.insert("alpha",   1);
    trie.insert("beta",    2);
    trie.insert("alphabet",42);      // “alpha” is prefix of this one

    if (auto p = trie.find("alphabet"))
        std::cout << "alphabet → " << *p << '\n';

    std::cout << "Keys:  "  << trie.key_count()
              << "\nNodes: " << trie.node_count()
              << "\nEdges: " << trie.edge_count() << '\n';

    auto mu = trie.memory_used();
    std::cout << "Memory used: " << mu.total()/1024.0 << " KiB\n";
}
#endif