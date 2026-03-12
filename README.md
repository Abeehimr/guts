# Guts — Local Version Control System

**Guts** is a custom, lightweight version control system written in C,heavily inspired by Git. It supports commit trees, branches, merges, and basic object storage using blobs and trees.

---

## Getting Started

### Compilation

To build **guts**, run:

```bash
gcc main.c -o guts -lz -lcrypto
```

Requires:
- `zlib`
- `OpenSSL` (for SHA-1)
- `Linux`
---

## Commands

### Internal Commands

These commands are primarily for internal or low-level inspection of guts objects:

| Command | Description |
|--------|-------------|
| `cat-file -c <hash>` | Show commit object details |
| `cat-file -p <hash>` | Print contents of a blob object |
| `hash-object -w <filename>` | Create and write a blob object from a file |
| `ls-tree <hash>` | List contents of a tree object |
| `write-tree [<path>]` | Create a tree object from current directory or specific path |
| `commit-tree <tree_hash> [<parent_hash> ...] -m <message>` | Commit a tree manually |

---

### External Commands

User-facing commands for working with your versioned project:

| Command | Description |
|---------|-------------|
| `init` | Initialize a new guts repository |
| `checkout <hash>` | Check out a specific commit |
| `branch <name>` | Create a new branch |
| `switch <name>` | Switch to a different branch |
| `set-user <name> <email>` | Set user identity for commits |
| `commit <message>` | Commit changes to current branch |
| `log` | Show commit history of current branch |
| `merge <branch_name>` | Merge another branch into the current one |



---

## NOTE

This is a personal/educational project.
