// ──────────────────────────── trie_pool.hpp ────────────────────────────
#pragma once
#include <array>
#include <cstdint>
#include <string_view>
#include <vector>
#include <utility>
#include <limits>
#include <cassert>

namespace fast {

/* -----------------------------------------------------------
 *  pool_trie  –  compact radix‑tree with pooled values
 * -----------------------------------------------------------
 *  • Key            : std::basic_string_view<CharT> (≤ 64 chars)
 *  • Value          : user‑provided template parameter T
 *  • Value storage  : contiguous pool  (std::vector<T>)
 *  • Node storage   : contiguous pool  (std::vector<Node>)
 *  • Complexity     : O(|key|) for insert / lookup
 *  • Memory / node  : 16 bytes (aligned)  ➜  ~1.2 MiB per 75 000 nodes
 * ----------------------------------------------------------*/
template<class T, class CharT = char>
class pool_trie
{
    static_assert(sizeof(CharT) == 1,
        "This implementation assumes 1‑byte code units (ASCII/UTF‑8).");

    // «invalid» index marker (4 Gi nodes / values before overflow)
    static constexpr std::uint32_t npos = std::numeric_limits<std::uint32_t>::max();

    struct Node
    {
        std::uint32_t first_child {npos};   // index of first child in siblings list
        std::uint32_t next_sibling{npos};   // linked list of siblings
        std::uint32_t value_idx  {npos};    // index in value_pool_ (npos → no value)
        CharT         label      {0};       // byte stored on edge leading here

        [[nodiscard]] bool has_value() const noexcept { return value_idx != npos; }
    };

    std::vector<Node> nodes_;     // node arena  (root is node 0)
    std::vector<T>    value_pool_;// value arena (dense)

    // ---- low‑level helpers ---------------------------------------------
    [[nodiscard]] std::uint32_t make_node(CharT lbl) {
        nodes_.emplace_back();
        nodes_.back().label = lbl;
        return static_cast<std::uint32_t>(nodes_.size() - 1);
    }

    // Return child with given label or npos
    [[nodiscard]] std::uint32_t find_child(std::uint32_t parent, CharT lbl) const noexcept {
        for (auto c = nodes_[parent].first_child;
             c != npos;
             c = nodes_[c].next_sibling)
        {
            if (nodes_[c].label == lbl) return c;
        }
        return npos;
    }

    // Insert child in *sorted* sibling list, return its index
    [[nodiscard]] std::uint32_t emplace_child(std::uint32_t parent, CharT lbl) {
        auto& p = nodes_[parent];
        std::uint32_t* link = &p.first_child;

        // keep siblings sorted → accelerates lookup slightly
        while (*link != npos && nodes_[*link].label < lbl)
            link = &nodes_[*link].next_sibling;

        if (*link != npos && nodes_[*link].label == lbl) return *link; // already exists

        const std::uint32_t new_idx = make_node(lbl);
        nodes_[new_idx].next_sibling = *link;
        *link = new_idx;
        return new_idx;
    }

public:
    pool_trie()             { nodes_.reserve(256);  nodes_.push_back(Node{}); /*root*/ }
    explicit pool_trie(std::size_t node_cap, std::size_t val_cap = 0)
    {
        nodes_.reserve(node_cap); value_pool_.reserve(val_cap);
        nodes_.push_back(Node{});
    }

    // --------------------------------------------------- INSERT ----------
    template<class U>
    T& insert(std::basic_string_view<CharT> key, U&& val)
    {
        assert(key.size() <= 64 && "key length > 64 not allowed.");

        std::uint32_t cur = 0; // root
        for (CharT ch : key)
            cur = emplace_child(cur, ch);

        if (!nodes_[cur].has_value()) {               // new entry
            nodes_[cur].value_idx = static_cast<std::uint32_t>(value_pool_.size());
            value_pool_.emplace_back(std::forward<U>(val));
        } else {                                      // overwrite
            value_pool_[nodes_[cur].value_idx] = std::forward<U>(val);
        }
        return value_pool_[nodes_[cur].value_idx];
    }

    // --------------------------------------------------- FIND ------------
    [[nodiscard]] T* find(std::basic_string_view<CharT> key) noexcept
    {
        std::uint32_t cur = 0;
        for (CharT ch : key) {
            cur = find_child(cur, ch);
            if (cur == npos) return nullptr;
        }
        return nodes_[cur].has_value() ? &value_pool_[nodes_[cur].value_idx] : nullptr;
    }
    [[nodiscard]] const T* find(std::basic_string_view<CharT> key) const noexcept
    { return const_cast<pool_trie*>(this)->find(key); }

    // --------------------------------------------------- CONTAINS --------
    [[nodiscard]] bool contains(std::basic_string_view<CharT> key) const noexcept
    { return find(key) != nullptr; }

    // --------------------------------------------------- SIZE / MEM ------
    [[nodiscard]] std::size_t nodes()  const noexcept { return nodes_.size(); }
    [[nodiscard]] std::size_t values() const noexcept { return value_pool_.size(); }

    [[nodiscard]] std::size_t bytes_nodes()  const noexcept
    { return nodes_.size() * sizeof(Node); }

    [[nodiscard]] std::size_t bytes_values() const noexcept
    { return value_pool_.size() * sizeof(T); }

    [[nodiscard]] std::size_t bytes_total()  const noexcept
    { return bytes_nodes() + bytes_values(); }

    // Disable copying (cheap to move)
    pool_trie(const pool_trie&)            = delete;
    pool_trie& operator=(const pool_trie&) = delete;

    pool_trie(pool_trie&&)            noexcept = default;
    pool_trie& operator=(pool_trie&&) noexcept = default;
};

} // namespace fast
// ────────────────────────────────────────────────────────────────────────