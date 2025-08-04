#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>
#include <zlib.h>
#include <openssl/sha.h>
#include <dirent.h>
#include <sys/stat.h>
#include <time.h>
#include <stdbool.h>

#define BUFFER_SIZE 65536UL
#define MAX_ENTRY_NAME_LENGTH 256
#define PATH_LENGTH 1024
#define HEX_HASH_LENGTH (SHA_DIGEST_LENGTH * 2)

void unix_epoch_to_date(char * dest, char* epoch) {
    time_t t = strtol(epoch, NULL, 10);
    struct tm *info;
    info = localtime(&t);
    strcpy(dest, asctime(info));
    dest[strlen(dest) - 1] = '\0';
}

void * xmalloc(size_t size) {
    void *ptr = malloc(size);
    if (ptr == NULL) {
        fprintf(stderr, "Memory allocation failed of size %ld: %s\n",size, strerror(errno));
        abort();
    }
    return ptr;
}

void * xrealloc(void *ptr, size_t size) {
    void *new_ptr = realloc(ptr, size);
    if (new_ptr == NULL) {
        fprintf(stderr, "Memory reallocation failed: %s\n", strerror(errno));
        abort();
    }
    return new_ptr;
}

size_t char_offset(const unsigned char* ptr, char c , size_t size){
    unsigned char * nptr = memchr(ptr, c, size);
    if (nptr == NULL) return size;
    return (size_t )(nptr - ptr);
}

size_t read_till(char** dest,unsigned char* source, char c, size_t size) {
    size_t len = char_offset(source, c ,size);
    *dest = xmalloc(len+1);
    memcpy(*dest, source, len);
    (*dest)[len] = '\0';
    return len;
}

int path_exists(const char * path) {
    struct stat sb;
    if (stat(path, &sb) == 0) {
        if (S_ISDIR(sb.st_mode)) {
            return 0; // is dir
        } else {
            return 1; // is file
        }
    } else {
        return -1; // DNE
    }
}

FILE* fd_open(const char * path, const char * mode) {
    if (path == NULL || mode == NULL) {
        fprintf(stderr, "Path or mode is NULL in fdopen: %s\n", strerror(errno));
        abort();
        return NULL;
    }
    char cur_path[1024];
    size_t size = strlen(path);
    size_t offset = 0;
    size_t len;
    int x;
    while (offset < size) {
        len = char_offset(path + offset, '/', size - offset);
        strncpy(cur_path + offset, path + offset, len);
        offset += len;
        cur_path[offset] = '\0';

        x = path_exists(cur_path);
        if (x != 0 && offset < size) { // create dir
            if (mkdir(cur_path, 0755) == -1) {
                fprintf(stderr, "Failed to create directory %s: %s\n", cur_path, strerror(errno));
                abort();
                return NULL;
            }
        }

        if (offset < size) {
            cur_path[offset] = '/'; // Add '/' to the end of the current path
            offset++; // Move past the '/' character
        }
    }
    return fopen(cur_path, mode);
}

int tz_offset(void) {
  time_t now = time(NULL);
  struct tm gmt = *gmtime(&now), loc = *localtime(&now);

  int sec = difftime(mktime(&loc), mktime(&gmt));
  int sign = (sec >= 0) ? 1 : -1;
  int abs = (sec >= 0) ? sec : -sec;

  int hours = abs / 3600;
  int mins = (abs & 3600) / 60;

  return sign * (hours * 100 + mins); // format: ±HHMM
}

void tz_to_str(char str[6], int tz) {
  char sign = (tz < 0) ? '-' : '+';
  if (sign == '-')
    tz *= -1;
  snprintf(str, 6, "%c%04d", sign, tz);
}




long get_file_size(FILE *file) {
    if (file == NULL) {
        fprintf(stderr, "File pointer is NULL: %s\n", strerror(errno));
        abort();
        return -1;
    }
    long size;
    fseek(file, 0, SEEK_END);
    size = ftell(file);
    fseek(file, 0, SEEK_SET);
    return size;
}

enum Object_type {
    BLOB = 1,
    TREE = 2,
    COMMIT = 3,
};



struct {
    void * data;
    size_t size;
    size_t capacity;
    size_t element_size;
} typedef vector;

void init_vector(vector *v, size_t initial_capacity, size_t element_size) {
    v->element_size = element_size;
    v->data = xmalloc(initial_capacity * element_size);
    v->size = 0;
    v->capacity = initial_capacity;
}

void push_back(vector *v, void *element) {
    if (v->size >= v->capacity) {
        v->capacity *= 2;
        v->data = xrealloc(v->data, v->capacity *v->element_size);
    }
    memcpy(v->data + v->size * v->element_size, element, v->element_size);
    v->size++;
}

void *get_item(vector *v, size_t index) {
    if (index >= v->size) {
        fprintf(stderr, "Index out of bounds: %zu\n", index);
        abort();
    }
    return v->data + index * v->element_size;
}

void free_vector(vector *v) {
    if (v == NULL || v->data == NULL) return;
    free(v->data);
    v->data = NULL;
    v->size = v->capacity = v->element_size = 0;
}

void sort_vector(vector * v, int (*cmp)(const void *, const void *)) {
    if (v == NULL || v->data == NULL || v->size <= 1) return;
    qsort(v->data, v->size, v->element_size, cmp);
}

void * find_vector(vector * v, void * key, int (*cmp)(const void *, const void *)) {
    if (v == NULL || v->data == NULL || v->size <= 0) return NULL;
    return bsearch(key, v->data, v->size, v->element_size, cmp);
}

struct {
    long mode;
    char name[MAX_ENTRY_NAME_LENGTH];
    unsigned char sha1_hash[SHA_DIGEST_LENGTH];
} typedef Tree_entry;


struct {
    char path[PATH_LENGTH];
    unsigned char sha1_hash[SHA_DIGEST_LENGTH + 1]; 
} typedef File_metadata;

int file_metadata_cmp(const void *a, const void *b) {
    const File_metadata *entry_a = (const File_metadata *)a;
    const File_metadata *entry_b = (const File_metadata *)b;
    return strcmp(entry_a->path, entry_b->path);
}


struct {
    char * username;
    char * email;
    char * timestamp;
    char * timezone;
} typedef User_data;

void free_user_data(User_data * u){
    if (u == NULL) return;
    if (u->username != NULL) free(u->username);
    if (u->email != NULL) free(u->email);
    if (u->timestamp != NULL) free(u->timestamp);
    if (u->timezone != NULL) free(u->timezone);
}

struct {
    unsigned char commit_hex_hash[HEX_HASH_LENGTH+1];
    unsigned char tree_hex_hash[HEX_HASH_LENGTH+1];
    vector* parents;
    User_data* author;
    User_data* committer;
    char * message;
} typedef Commit_entry;

void init_commit_entry(Commit_entry* c) {
    if (c == NULL) {
        fprintf(stderr, "Commit entry is null in init_commit_entry: %s", strerror(errno));
        abort();
        return;
    }
    c->parents = xmalloc(sizeof(vector));
    init_vector(c->parents, 10, sizeof(unsigned char[HEX_HASH_LENGTH + 1]) );
    c->author = xmalloc(sizeof(User_data));
    c->committer = xmalloc(sizeof(User_data));
}

void free_commit_entry(Commit_entry* c) {
    if (c == NULL) return;
    free_vector(c->parents);
    free_user_data(c->author);
    if (c->author) free(c->author);
    free_user_data(c->committer);
    if (c->committer) free(c->committer);
    if (c->message) free(c->message);
}


struct {
    int type;
    unsigned char *content;
    long content_size;
    unsigned char *uncompressed_data;
    long uncompressed_size;
    unsigned char *compressed_data;
    long compressed_size;
    unsigned char sha1_hash[SHA_DIGEST_LENGTH];
    char hex_hash[SHA_DIGEST_LENGTH * 2 + 1];
    char path[55]; // Optional: path to the blob file
    char dir_path[17];

    // only for tree;
    // Tree_entry *entries;
} typedef Object;


int free_object(Object *obj) {
    if (obj == NULL) return 0;

    if (obj->content != NULL) {
        free(obj->content);
    }
    if (obj->uncompressed_data != NULL) {
        free(obj->uncompressed_data);
    }
    if (obj->compressed_data != NULL) {
        free(obj->compressed_data);
    }
    return 0;
}

int create_dir_path(Object *obj) {
    if (obj == NULL) {
        fprintf(stderr, "Blob object pointer is NULL: %s\n", strerror(errno));
        abort();
        return -1;
    }
    // Create the directory path based on the first two characters of the hex hash
    snprintf(obj->dir_path, sizeof(obj->dir_path), ".guts/objects/%c%c/", obj->hex_hash[0], obj->hex_hash[1]);
    obj->dir_path[sizeof(obj->dir_path) - 1] = '\0'; // Ensure null termination
    return 0;
}

int create_path(Object *obj) {
    if (obj == NULL) {
        fprintf(stderr, "Blob object pointer is NULL: %s\n", strerror(errno));
        abort();
        return -1;
    }
    // Create the full path for the blob object file
    snprintf(obj->path, sizeof(obj->path), ".guts/objects/%c%c/%s", obj->hex_hash[0], obj->hex_hash[1], obj->hex_hash + 2);
    obj->path[sizeof(obj->path) - 1] = '\0'; // Ensure null termination
    return 0;
}

int init_object(Object *obj, int type) {
    if (obj == NULL) {
        fprintf(stderr, "Blob object pointer is NULL: %s\n", strerror(errno));
        abort();
        return -1;
    }
    obj->type = type;
    obj->content = NULL;
    obj->content_size = 0;
    obj->uncompressed_data = NULL;
    obj->uncompressed_size = 0;
    obj->compressed_data = NULL;
    obj->compressed_size = 0;
    memset(obj->sha1_hash, 0, SHA_DIGEST_LENGTH);
    memset(obj->hex_hash, 0, sizeof(obj->hex_hash));
    obj->path[0] = '\0'; // Initialize path to an empty string
    obj->dir_path[0] = '\0'; // Initialize dir_path to an
    return 0;
}

void display_tree_entry(Tree_entry * e){
    printf("%ld ", e->mode);

    if (e->mode == 040000) printf("tree ");
    else if (e->mode == 0100644) printf("blob ");
    else if (e->mode == 0100755) printf("executable blob ");
    else if (e->mode == 0120000) printf("symlink ");
    else if (e->mode == 0160000) printf("commit ");
    else {
        fprintf(stderr, "Unknown mode: %ld while parsing Tree: %s\n", e->mode, strerror(errno));
        abort();
        return;
    }

    for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
        printf("%02x", e->sha1_hash[i]);
    }
    printf("\t%s\n", e->name);
}

int parse_tree(Object * obj, vector* tree )  { // assumes the object format is correct
    if (obj == NULL || obj->uncompressed_data == NULL || obj->uncompressed_size <= 0) {
        fprintf(stderr, "Blob object or uncompressed data is NULL: %s\n", strerror(errno));
        abort();
        return -1;
    }
    // find 1st \0
    
    if (tree == NULL) {
        fprintf(stderr, "Tree vector is NULL in parse_tree: %s\n", strerror(errno));
        abort();
        return -1;
    }


    size_t offset = 0;
    size_t len;
    offset += char_offset(obj->uncompressed_data, '\0', obj->uncompressed_size);
    offset += 1; // move past the \0
    char * mode_str;
    while (offset < obj->uncompressed_size) { // in the end 
        // find next \0
        Tree_entry entry;
        offset += read_till(&mode_str, obj->uncompressed_data + offset, ' ', obj->uncompressed_size - offset);
        
        offset++;
       
        entry.mode = strtol(mode_str, NULL, 10); // convert mode to long
        free(mode_str); // free the mode string
        
        len = char_offset(obj->uncompressed_data + offset, '\0', obj->uncompressed_size - offset);
        memcpy(entry.name, obj->uncompressed_data + offset, len);
        entry.name[len] = '\0'; // Null-terminate the name
        offset += len + 1; // move past the \0


        memcpy(entry.sha1_hash, obj->uncompressed_data + offset, 20);
        offset += 20;

        push_back(tree, &entry);
    }
}

int read_object(Object * obj,const char * hex_hash){
    if (obj == NULL || hex_hash == NULL) { // internal problem
        fprintf(stderr, "object of hash is null in read_object: %s\n", strerror(errno));
        abort();
        return -1;
    }
    memcpy(obj->hex_hash, hex_hash, HEX_HASH_LENGTH);
    obj->hex_hash[HEX_HASH_LENGTH] = '\0'; //
    
    create_dir_path(obj);
    create_path(obj);

    FILE *objectFile;
    if ((objectFile = fopen(obj->path, "rb")) == NULL) { // means file DNE
        fprintf(stderr, "Object file %s does not exist: %s\n", obj->path, strerror(errno));
        return -1;
    }

    // Get file size
    obj->compressed_size = get_file_size(objectFile);
    // Read the file content
    obj->compressed_data = xmalloc(obj->compressed_size);
    
    if ((fread(obj->compressed_data, 1, obj->compressed_size, objectFile)) != obj->compressed_size) {
        fprintf(stderr, "Failed to read object file: %s\n", strerror(errno));
        fclose(objectFile);
        free_object(obj);
        abort();
        return -1;
    }

    fclose(objectFile);
}


int create_object(Object *obj) {
    if (obj == NULL) {
        fprintf(stderr, "object pointer is NULL in create_object function: %s\n", strerror(errno));
        abort();
        return -1;
    }
    if (obj->content == NULL || obj->content_size < 0) {
        fprintf(stderr, "content is NULL or size( %ld ) is invalid in create_object function: %s\n",obj->content_size, strerror(errno));
        abort();
        return -1;
    }
    // string of size
    char size_str[64];
    sprintf(size_str, "%ld", obj->content_size);

    obj->uncompressed_size = 8 + strlen(size_str) + obj->content_size; // "blob " + size + '\0' + content
    obj->uncompressed_data = xmalloc(obj->uncompressed_size);
    //sprintf(obj->uncompressed_data, "blob %s\0%s", size_str, obj->content);
    int offset = 0;
    if (obj->type == BLOB) {
        memcpy(obj->uncompressed_data, "blob ", 5);
        offset += 5;
    }
    else if (obj->type == TREE) {
        memcpy(obj->uncompressed_data, "tree ", 5);
        offset += 5;
    }
    else if (obj->type == COMMIT) {
        memcpy(obj->uncompressed_data, "commit ", 7);
        offset += 7;
    }
    else {
        fprintf(stderr, "Invalid object type: %s\n" ,strerror(errno));
        abort();
        return -1;
    }
    memcpy(obj->uncompressed_data + offset, size_str, strlen(size_str));
    offset += strlen(size_str);
    obj->uncompressed_data[offset] = '\0'; // Null-terminate the header
    offset += 1;
    memcpy(obj->uncompressed_data + offset, obj->content, obj->content_size); // Copy the content
    obj->uncompressed_size = offset + obj->content_size;
    return 0;
};



int hash_to_hex(const unsigned char *hash, char *hex_hash) {
    if (hash == NULL || hex_hash == NULL) {
        fprintf(stderr, "Hash or hex_hash pointer is NULL: %s\n", strerror(errno));
        abort();
        return -1;
    }
    for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
        sprintf(&(hex_hash[i * 2]), "%02x", hash[i]);
    }
    hex_hash[HEX_HASH_LENGTH] = '\0'; // Null-terminate the hex string
    return 0;
}

int compute_sha1_hash(Object *obj) {
    if (obj == NULL || obj->uncompressed_data == NULL || obj->uncompressed_size <= 0) {
        fprintf(stderr, "Blob object or uncompressed data is NULL: %s\n" , strerror(errno));
        abort();
        return -1;
    }
    // computing the sha1 hash of the blob

    SHA1(obj->uncompressed_data, obj->uncompressed_size, obj->sha1_hash);

    // Convert the SHA1 hash to hex format
    hash_to_hex(obj->sha1_hash, obj->hex_hash);

    return 0;
}

void extact_content(Object * obj) {
    if (obj == NULL || obj->uncompressed_data == NULL || obj->uncompressed_data <= 0) {
        fprintf(stderr, "Blob object or compressed data is NULL: %s\n" , strerror(errno));
        abort();
        return;
    }

    size_t offset = strlen(obj->uncompressed_data) + 1; // +1 for the null terminator
    obj->content_size = obj->uncompressed_size - offset; // size of the content
    obj->content = xmalloc(obj->content_size);
    memcpy(obj->content, obj->uncompressed_data + offset, obj->content_size);
}

long decompress_object(Object * obj) {
    if (obj == NULL || obj->compressed_data == NULL || obj->compressed_size <= 0) {
        fprintf(stderr, "Blob object or compressed data is NULL: %s\n" , strerror(errno));
        abort();
        return -1;
    }

    if (obj->uncompressed_data == NULL) {
        obj->uncompressed_data = xmalloc(BUFFER_SIZE); // Adjust as needed
        // if (obj->uncompressed_data == NULL) {
        //     fprintf(stderr, "Failed to allocate memory for uncompressed data\n");
        //     return -1;
        // }
    }

    z_stream stream = {
        .next_in = obj->compressed_data,
        .avail_in = obj->compressed_size,
        .next_out = obj->uncompressed_data,
        .avail_out = BUFFER_SIZE, // Adjust as needed
    };
    
    if (inflateInit(&stream) != Z_OK) {
        fprintf(stderr, "inflateInit failed: %s\n", strerror(errno));
        abort();
        return -1;
    }
    
    int ret = inflate(&stream, Z_FINISH);
    if (ret != Z_STREAM_END) {
        fprintf(stderr, "inflate failed of object %s: %d %s\n", obj->hex_hash, ret, strerror(errno));
        inflateEnd(&stream);
        abort();
        return -1;
    }
    
    inflateEnd(&stream);
    obj->uncompressed_size = stream.total_out; // Update the size of uncompressed data
   
    return stream.total_out; // Return the size of decompressed data
}

long compress_blob(Object * obj) {
   if (obj == NULL || obj->uncompressed_data == NULL || obj->uncompressed_size <= 0) {
        fprintf(stderr, "Blob object or uncompressed data is NULL: %s\n" , strerror(errno));
        abort();
        return -1;
    }
    uLongf compressed_size = compressBound(obj->uncompressed_size);
    obj->compressed_data = xmalloc(compressed_size);
    obj->compressed_size = compressed_size;
    // if (obj->compressed_data == NULL) {
    //     fprintf(stderr, "Failed to allocate memory for compressed data: %s\n");
    //     return -1;
    // }
    
    int ret = compress(obj->compressed_data, &compressed_size, obj->uncompressed_data, obj->uncompressed_size);
    if (ret != Z_OK) {
        fprintf(stderr, "Compression failed: %d %s\n", ret, strerror(errno));
        free_object(obj);
        abort();
        return -1;
    }    
    return compressed_size;
}


// int cmd_write_tree(int argc, char *argv[]) {
//   (void)argc;
//   (void)argv;

//   unsigned char tree_hash[OBJ_HASH_LEN];
//   int ret = traverse(tree_hash, ".");
//   if (ret == 0) {
//     for (int i = 0; i < OBJ_HASH_LEN; i++)
//       printf("%02x", tree_hash[i]);
//     printf("\n");
//   }
//   return ret;
// }

void write_object(Object *obj) {
    if (obj == NULL) {
        fprintf(stderr, "Object pointer is NULL in write_object function: %s\n", strerror(errno));
        abort();
        return;
    }
    // Create the directory path
    create_dir_path(obj);
    create_path(obj);

    if (mkdir(obj->dir_path, 0755) == -1 && errno != EEXIST) {
        fprintf(stderr, "Failed to create directory %s: %s\n", obj->dir_path, strerror(errno));
        free_object(obj);
        abort();
        return;
    }

    // Open the file for writing
    FILE *file = fopen(obj->path, "wb");
    if (file == NULL) {
        fprintf(stderr, "Failed to open file %s for writing: %s\n", obj->path, strerror(errno));
        free_object(obj);
        abort();
        return;
    }

    // Write the compressed data to the file
    if (fwrite(obj->compressed_data, 1, obj->compressed_size, file) != obj->compressed_size) {
        fprintf(stderr, "Failed to write to file %s: %s\n", obj->path, strerror(errno));
        fclose(file);
        free_object(obj);
        abort();

        return;
    }

    fclose(file);
}

int create_blob(unsigned char * const tree_hash_rlt,const char *path){
    FILE *file = fopen(path, "rb");
    if (!file) {
        fprintf(stderr, "Failed to open file %s in create_blob: %s\n", path, strerror(errno));
        abort();
        return -1;
    }
    // Read file content

    Object obj;
    init_object(&obj, BLOB); // Initialize the object as a BLOB
    obj.content_size = get_file_size(file);

    obj.content = xmalloc(obj.content_size);
    if (fread(obj.content, 1, obj.content_size, file) != obj.content_size) {
        fprintf(stderr, "Failed to read file %s in create_blob: %s\n", path, strerror(errno));
        fclose(file);
        free_object(&obj);
        abort();
        return 1;
    }
    fclose(file);

    // create the blob object
    create_object(&obj);
    // computing the sha1 hash of the blob
    compute_sha1_hash(&obj);
    memcpy(tree_hash_rlt, obj.sha1_hash, SHA_DIGEST_LENGTH);

    //printf("%s\n", obj.hex_hash);
    // Compressing the blob
    compress_blob(&obj);
    // Constructing the new file's path
    
    write_object(&obj);
    free_object(&obj);
}

int tree_entry_cmp(const void *a, const void *b) {
    const Tree_entry *entry_a = (const Tree_entry *)a;
    const Tree_entry *entry_b = (const Tree_entry *)b;
    return strcmp(entry_a->name, entry_b->name);
}


int create_tree_payload(Object* obj, vector *tree) {
    if (obj == NULL || tree == NULL) {
        fprintf(stderr, "Object or tree vector is NULL in create_tree_payload: %s\n", strerror(errno));
        abort();
        return -1;
    }

    qsort(tree->data, tree->size, tree->element_size,tree_entry_cmp);

    // for (size_t i = 0; i < tree->size; i++) {
    //     Tree_entry *entry = get_item(tree, i);
    //     printf("mode: %ld, name: %s, hash: ", entry->mode, entry->name);
    //     for (int j = 0; j < SHA_DIGEST_LENGTH; j++)
    //         printf("%02x", entry->sha1_hash[j]);
    //     printf("\n");
    // }

    // Calculate the size of the payload
    obj->content_size = 0;
    for (size_t i = 0; i < tree->size; i++) {
        Tree_entry *entry = get_item(tree, i);
        // ASSUMPTION: MODE IS ATMOST 8 BYTES LONG
        obj->content_size += 10 + strlen(entry->name) + SHA_DIGEST_LENGTH; // "mode name\0hash"
    }
    
    obj->content = xmalloc(obj->content_size);
    char *ptr = obj->content;
    unsigned char mode_str[10];
    size_t mode_len = 0;
    size_t name_len = 0;
    obj->content_size = 0;
    for (size_t i = 0; i < tree->size; i++) {
        Tree_entry *entry = get_item(tree, i);
        sprintf(mode_str, "%ld", entry->mode);
        mode_len = strlen(mode_str);
        name_len = strlen(entry->name);
        memcpy(ptr, mode_str, mode_len);
        ptr[mode_len] = ' ';
        memcpy(ptr + mode_len + 1, entry->name, name_len);
        ptr[mode_len + 1 + name_len] = '\0'; // Null-terminate the name
        memcpy(ptr + mode_len + name_len + 2, entry->sha1_hash, SHA_DIGEST_LENGTH);
        ptr += mode_len + name_len + 2 + SHA_DIGEST_LENGTH; // Move the pointer forward
        obj->content_size += mode_len + 1 + name_len + 1 + SHA_DIGEST_LENGTH; // "mode name\0hash"
    }
    return 0;
}



size_t create_tree(unsigned char *tree_hash_rlt, char *path) {
    if (tree_hash_rlt == NULL || path == NULL) {
        fprintf(stderr, "Invalid arguments to create_tree: %s\n", strerror(errno));
        abort();
        return 0;
    }
    
    DIR *dir = opendir(path);
    if (!dir) {
        fprintf(stderr, "Failed to open root dir in create_tree: %s\n", strerror(errno));
        abort();
        return 0;
    }

    vector tree;
    init_vector(&tree, 10, sizeof(Tree_entry));

    size_t no_of_elements;
    struct dirent *entry = NULL;
    while ((entry = readdir(dir))) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0 ||
            strcmp(entry->d_name, ".guts") == 0 || strcmp(entry->d_name, "guts") == 0)
            continue;

        char entry_path[PATH_LENGTH];
        snprintf(entry_path, sizeof(entry_path), "%s/%s", path, entry->d_name);
        
        struct stat st;
        if (lstat(entry_path, &st) == -1){
        
            fprintf(stderr, "lstat failed for <%s>: %s\n", entry_path, strerror(errno));
            abort();
            return 0;
        }

        int mode = 0;
        if (S_ISREG(st.st_mode))
            mode = (st.st_mode & 0111) ? 0100755 : 0100644;
        else if (S_ISLNK(st.st_mode))
            mode = 0120000;
        else if (S_ISDIR(st.st_mode))
            mode = 040000;
        else{
            fprintf(stderr,"invalid mode: %d %s", st.st_mode, strerror(errno));
            abort();
            return -1;
        }

        Tree_entry tree_entry;
        tree_entry.mode = mode;
        strcpy(tree_entry.name, entry->d_name);
        
        if (mode == 040000) { // if dir
            no_of_elements = create_tree(tree_entry.sha1_hash, entry_path);
        }
        else { // if file
            create_blob(tree_entry.sha1_hash, entry_path);
            no_of_elements = 1;
        }
        // Add the entry to the tree
        if (no_of_elements)
            push_back(&tree, &tree_entry);
    }
    size_t no_of_items = tree.size;
    if (! no_of_items) return 0;
    Object obj;
    init_object(&obj, TREE); // Initialize the object as a TREE
    // Create the tree payload
    create_tree_payload(&obj, &tree);


    create_object(&obj);

    compute_sha1_hash(&obj);
    memcpy(tree_hash_rlt, obj.sha1_hash, SHA_DIGEST_LENGTH + 1);
    // Compress the tree object
    compress_blob(&obj);
    // Create the directory path for the tree object
    write_object(&obj);
    
    free_object(&obj);
    free_vector(&tree); // Free the vector after use
    
    closedir(dir);
    return no_of_items;
}

char * get_user_data() {
    FILE * file = fopen(".guts/guts", "r");
    if (file == NULL) {
        fprintf(stderr, "couldn't open guts\n Please run set-user command first\n");
        return NULL;
    }
    size_t size = get_file_size(file);
    char * data = xmalloc(size); // +1 for null terminator
    if (fread(data, 1, size, file) != size) {
        fprintf(stderr, "Failed to read guts file: %s\n", strerror(errno));
        fclose(file);
        free(data);
        return NULL;
    }
    data[size] = '\0'; // Null-terminate the string
    fclose(file);
    return data;
}

int create_commit_payload(Object* obj, unsigned char* tree_hex_hash, vector* parents,const char* message) {
    if (obj == NULL || tree_hex_hash == NULL || parents == NULL || message == NULL) {
        fprintf(stderr, "Invalid arguments to create_commit_payload: %s\n", strerror(errno));
        abort();
        return -1;
    }
    char* user_data = get_user_data();
    if (user_data == NULL) {
        return -1; // User data not set, cannot create commit payload
    }
    size_t user_data_len = strlen(user_data);
    size_t message_len = strlen(message);
    char time_str[15];
    sprintf(time_str, "%ld", time(NULL));
    size_t time_len = strlen(time_str);
    int utc = tz_offset();
    char utc_str[6];
    tz_to_str(utc_str, utc);


    // ROUGH ESTIMATE OF CONTENT SIZE
    obj->content_size = 0;
    obj->content_size += 6 + HEX_HASH_LENGTH; // "tree " + tree_sha + \n
    obj->content_size += parents->size * (8 + HEX_HASH_LENGTH); // "parent " + parent_sha + \n
    obj->content_size += user_data_len + 8; // user data + \n
    obj->content_size += 21; // time + \n
    obj->content_size += user_data_len + 11; // user data + \n
    obj->content_size += time_len + 7; // time + \n
    obj->content_size += message_len + 2; // "message " + message + \n

    obj->content = xmalloc(obj->content_size);
    size_t offset = 0;
    // Add tree SHA
    memcpy(obj->content + offset, "tree ", 5);
    offset += 5;
    memcpy(obj->content + offset, tree_hex_hash, HEX_HASH_LENGTH);
    offset += HEX_HASH_LENGTH;
    obj->content[offset++] = '\n'; // Newline after tree SHA
    for (int i = 0; i < parents->size; i++) {
        unsigned char *parent_sha = get_item(parents, i);
        memcpy(obj->content + offset, "parent ", 7);
        offset += 7;
        memcpy(obj->content + offset, parent_sha, HEX_HASH_LENGTH);
        offset += HEX_HASH_LENGTH;
        obj->content[offset++] = '\n'; // Newline after parent SHA
    }
    // Add user data
    memcpy(obj->content + offset, "author ", 7);
    offset += 7;
    memcpy(obj->content + offset, user_data, user_data_len);
    offset += user_data_len;
    obj->content[offset++] = ' ';
    memcpy(obj->content + offset, time_str, time_len);
    offset += time_len;
    obj->content[offset++] = ' ';
    memcpy(obj->content + offset, utc_str, 5);
    offset += 5;
    obj->content[offset++] = '\n';
    // Add committer data
    memcpy(obj->content + offset, "committer ", 10);
    offset += 10;
    memcpy(obj->content + offset, user_data, user_data_len);
    offset += user_data_len;
    obj->content[offset++] = ' ';
    memcpy(obj->content + offset, time_str, time_len);
    offset += time_len;
    obj->content[offset++] = ' ';
    memcpy(obj->content + offset, utc_str, 5);
    offset += 5;
    obj->content[offset++] = '\n';
    obj->content[offset++] = '\n';
    // Add commit message
    memcpy(obj->content + offset, message, message_len);
    offset += message_len;
    obj->content_size = offset; // Update content size

    free(user_data); // Free user data after use
    return 0;
}



void display_user_data(User_data* u) {
    if (u == NULL) {
        fprintf(stderr, "User is null in display_user_data: %s\n", strerror(errno));
        abort();
        return;
    }
    printf("%s <%s> %s %s\n", u->username, u->email, u->timestamp, u->timezone);
}

void parse_user_data(unsigned char * ptr, size_t* offset, size_t size, User_data* user) {
    if (ptr == NULL || user == NULL) {
        fprintf(stderr, "Pointer or user data is NULL in parse_user_data: %s\n", strerror(errno));
        abort();
        return;
    }
    *offset += read_till(&(user->username), ptr + *offset, ' ', size - *offset);
    *offset += 2;
    *offset += read_till(&(user->email), ptr + *offset, '>', size - *offset);
    *offset += 2;
    *offset += read_till(&(user->timestamp), ptr + *offset, ' ', size - *offset);
    *offset += 1;
    *offset += read_till(&(user->timezone), ptr + *offset, '\n', size - *offset);
    *offset += 1;
}



void display_commit_entry(Commit_entry * c) {
    if (c == NULL || c->author == NULL || c->committer == NULL || c->message == NULL) {
        fprintf(stderr, "Commit entry is null in display_commit_entry: %s" , strerror(errno));
        abort();
        return;
    }
    char date[30];

    printf("\033[1;33mCommit %20s\n\033[0m", c->commit_hex_hash);

    printf("Author: %s <%s>\n", c->author->username, c->author->email);
    unix_epoch_to_date(date, c->author->timestamp);
    printf("Date: %s %s\n", date, c->author->timezone);

    printf("Committer: %s <%s>\n", c->committer->username, c->committer->email);
    unix_epoch_to_date(date, c->committer->timestamp);
    printf("Date: %s %s\n", date, c->committer->timezone);

    printf("\t%s\n", c->message);
}

void get_tree_hash(Object * obj, char * tree_hex_hash) {
    // partial parse commit to get tree hex hash
    if (obj == NULL || obj->uncompressed_data == NULL || obj->uncompressed_size <= 0) {
        fprintf(stderr, "Object or uncompressed data is NULL in get_tree_hash: %s\n", strerror(errno));
        abort();
        return;
    }
    if (obj->type != COMMIT) {
        fprintf(stderr, "Object type is not COMMIT in get_tree_hash: %s\n", strerror(errno));
        abort();
        return;
    }

    if (tree_hex_hash == NULL) {
        fprintf(stderr, "Tree hex hash pointer is NULL in get_tree_hash: %s\n", strerror(errno));
        abort();
        return;
    }
    // code

    size_t offset = 0;
    offset += strlen(obj->uncompressed_data) + 1; // move to \0 + 1
    unsigned char *ptr = memchr(obj->uncompressed_data + offset, ' ', obj->uncompressed_size - offset);
    if (!ptr) {
        fprintf(stderr, "Invalid object format in get_tree_hash: %s\n", strerror(errno));
        abort();
        return;
    }
    offset += ptr - (obj->uncompressed_data + offset) + 1; // move to \space + 1
    memcpy(tree_hex_hash, obj->uncompressed_data + offset, HEX_HASH_LENGTH);
    tree_hex_hash[HEX_HASH_LENGTH] = '\0';
}


Commit_entry* parse_commit(Object* obj){ // ASSUMPTION: FORMAT IS CORRECT
    if (obj == NULL || obj->uncompressed_data == NULL || obj->uncompressed_size <= 0) {
        fprintf(stderr, "object or data is null: %s\n",strerror(errno));
        abort();
    }

    char type[15];
    Commit_entry* commit_entry = xmalloc(sizeof(Commit_entry));
    init_commit_entry(commit_entry);
    memcpy(commit_entry->commit_hex_hash, obj->hex_hash, HEX_HASH_LENGTH + 1);
    size_t offset = 0;
    size_t len;
    unsigned char* ptr;

    offset += strlen(obj->uncompressed_data) + 1; // move to \0 + 1
    ptr = memchr(obj->uncompressed_data + offset, ' ', obj->uncompressed_size - offset); // find \space
    offset += ptr - (obj->uncompressed_data + offset);
    offset++;
    memcpy(commit_entry->tree_hex_hash, obj->uncompressed_data + offset, HEX_HASH_LENGTH);
    commit_entry->tree_hex_hash[HEX_HASH_LENGTH] = '\0';
    offset += HEX_HASH_LENGTH + 1;
    

    int i = 0;
    unsigned char parent_hash[HEX_HASH_LENGTH + 1];

    while (1) {
        ptr = memchr(obj->uncompressed_data + offset, ' ', obj->uncompressed_size - offset); // find \n
        len = ptr - (obj->uncompressed_data + offset);
        memcpy(type, obj->uncompressed_data + offset, len);
        offset += len + 1; // move to \space + 1

        if (strcmp(type, "parent") == 0) {
            memcpy(parent_hash, obj->uncompressed_data + offset, HEX_HASH_LENGTH);
            parent_hash[HEX_HASH_LENGTH] = '\0';
            push_back(commit_entry->parents, parent_hash);
            offset += HEX_HASH_LENGTH + 1;
        }
        else {
            break;
        }
    }

    parse_user_data(obj->uncompressed_data, &offset, obj->uncompressed_size, commit_entry->author); // author

    // commiter
    offset += char_offset(obj->uncompressed_data + offset, ' ', obj->uncompressed_size - offset) + 1;
    
    
    parse_user_data(obj->uncompressed_data, &offset, obj->uncompressed_size, commit_entry->committer); // committer
    
    len = obj->uncompressed_size - offset;
    commit_entry->message = xmalloc(len+1);
    memcpy(commit_entry->message, obj->uncompressed_data+offset, len);    
    commit_entry->message[len] = '\0';

    return commit_entry;

    // display_commit_entry(commit_entry);
    // free_commit_entry(commit_entry);
}

int create_commit(char * commit_hex_hash ,unsigned char* tree_hex_hash, vector* parents,const char* message) {
    if (commit_hex_hash == NULL || tree_hex_hash == NULL || parents == NULL || message == NULL) {
        fprintf(stderr, "Invalid arguments to create_commit: %s\n", strerror(errno));
        abort();
        return -1;
    }
    
    Object obj;
    init_object(&obj, COMMIT);
    // create payload
    if (create_commit_payload(&obj, tree_hex_hash, parents, message) != 0) {
        free_object(&obj);
        return -1; // Error in creating commit payload
    }
    // create_object
    create_object(&obj);
    // compute_sha1_hash
    compute_sha1_hash(&obj);
    // compress
    compress_blob(&obj);
    // write
    write_object(&obj);
    // display hash

    hash_to_hex(obj.sha1_hash, obj.hex_hash);
    memcpy(commit_hex_hash, obj.hex_hash, HEX_HASH_LENGTH + 1);
    // Clean up
    free_object(&obj);
    return 0;
}


void display_log(unsigned char* tree_hex_hash) {
    if (tree_hex_hash == NULL) {
        fprintf(stderr, "tree hash is null in display_log: %s\n", strerror(errno));
        abort();
        return;
    }

    Object obj;
    init_object(&obj, COMMIT);
    Commit_entry * commit;

    while (1) {
        // find the commit
        read_object(&obj, tree_hex_hash);
        decompress_object(&obj);
        // parse it
        commit = parse_commit(&obj);
        // display
        display_commit_entry(commit);
        // move to 1st parent if any
        if (commit->parents->size) {
            memcpy(tree_hex_hash, (unsigned char *)get_item(commit->parents, 0), HEX_HASH_LENGTH);
            tree_hex_hash[HEX_HASH_LENGTH] = '\0';
            free_commit_entry(commit);
        }
        else {
            free_commit_entry(commit);
            break;
        }
    }
    free_object(&obj);
    puts("[END]");
}



int get_head_branch_path(char * path) { // ASUMPTION: HEAD IS NOT DETACHED
    if (path == NULL) {
        fprintf(stderr, "given address is null in get_head_branch_path: %s\n", strerror(errno));
        abort();
        return -1; 
    }
    
    FILE *headFile = fopen(".guts/HEAD", "r");
    if (headFile == NULL) {
        fprintf(stderr, "Failed to open .guts/HEAD file: %s\n", strerror(errno));
        abort();
        return -1;
    }


    size_t size = get_file_size(headFile);

    if (fread(path,1, 5, headFile ) < 5){
        fprintf(stderr, "invalid HEAD file format: %s\n", strerror(errno));
        abort();
        return -1;
    }
    if (strncmp(path, "ref: ", 5) != 0) {
        fclose(headFile);
        return -1;
    }
    strcpy(path, ".guts/");
    if (fread(path+strlen(path), 1, size - 5, headFile) < size - 5) {
        fprintf(stderr, "unable to read HEAD file: %s\n", strerror(errno));
        abort();
        return -1;
    }
    size ++;
    path[size] = '\0'; // Null-terminate the string
    if (path[size - 1] == '\n') {
        path[size - 1] = '\0'; // Remove the newline character
    }
    fclose(headFile);
}

int get_head_branch_name(char * branch_name) { // ASUMPTION: HEAD IS NOT DETACHED
    if (branch_name == NULL) {
        fprintf(stderr, "given address is null in get_head_branch_name: %s\n", strerror(errno));
        abort();
        return -1; 
    }
    
    char path[PATH_LENGTH];
    if (get_head_branch_path(path) == -1){ // DETACHED HEAD
        return -1;
    }
    
    if (strncmp(path, ".guts/refs/heads/", 17) != 0) {
        fprintf(stderr, "Invalid branch path format: %s\n", strerror(errno));
        return -1;
    }
    
    strcpy(branch_name, path + 17); // Copy the branch name
    return 0;
}

int get_head_hash(char * hash){
    // return 0 if HEAD is not detached
    // return 1 if HEAD is detached
    if (hash == NULL) {
        fprintf(stderr, "given address is null in get_head_hash: %s\n", strerror(errno));
        abort();
        return -1; 
    }

    char path[100];
    if (get_head_branch_path(path) == -1){ // DETACHED HEAD
        FILE *headFile = fopen(".guts/HEAD", "r");
        if (headFile == NULL) {
            fprintf(stderr, "Failed to open .guts/HEAD file: %s\n", strerror(errno));
            abort();
            return -1;
        }
        size_t size = get_file_size(headFile);
        if (size != HEX_HASH_LENGTH) {
            fprintf(stderr, "Invalid HEAD file format: %s\n", strerror(errno));
            fclose(headFile);
            abort();
            return -1;
        }
        if (fread(hash, 1, HEX_HASH_LENGTH, headFile) < HEX_HASH_LENGTH) {
            fprintf(stderr, "unable to read HEAD file: %s\n", strerror(errno));
            fclose(headFile);
            abort();
            return -1;
        }
        hash[HEX_HASH_LENGTH] = '\0'; // Null-terminate the string
        fclose(headFile);
        return 1;
    }


    FILE * branchFile = fopen(path, "r");
    if (branchFile == NULL) {
        fprintf(stderr, "Failed to open %s file: %s\n",path, strerror(errno));
        abort();
        return -1;
    }

    size_t size = get_file_size(branchFile);
    if (size != HEX_HASH_LENGTH) {
        fprintf(stderr, "Nothing Committed to current branch\n");
        fclose(branchFile);
        hash[0] = '\0'; // Set hash to empty string
        return -1;
    }
    if (fread(hash, 1, size, branchFile) < size) {
        fprintf(stderr, "unable to read %s file: %s\n",path, strerror(errno));
        abort();
        return -1;
    }
    hash[size] = '\0';
    fclose(branchFile);
    return 0;
}

void write_to_file(char *path, char * content, size_t size) {
    if (path == NULL || content == NULL || size == 0) {
        fprintf(stderr, "Path or content is NULL in write_to_file: %s\n", strerror(errno));
        abort();
        return;
    }
    FILE *file = fopen(path, "w");
    if (file == NULL) {
        fprintf(stderr, "Failed to open file %s for writing: %s\n", path, strerror(errno));
        abort();
        return;
    }
    if (fwrite(content, 1, size, file) < size) {
        fprintf(stderr, "Failed to write to file %s: %s\n", path, strerror(errno));
        fclose(file);
        abort();
        return;
    }
    fclose(file);
}

void create_branch(const char * name) {
    if (name == NULL || strlen(name) == 0) {
        fprintf(stderr, "Branch name is NULL in create_branch: %s\n", strerror(errno));
        abort();
        return;
    }
    // find the current commit
        // check head
        // find the commit in the current branch
    // if no commit then leave this one empty too
    // else copy that hash into this one too

    char path[PATH_LENGTH];
    strcpy(path , ".guts/refs/heads/");
    strcpy(path + strlen(path), name);
    

    if (path_exists(path) == 1) {
        fprintf(stdin, "BRANCH ALREADY EXISTS\n");
        return;
    }

    char commit_hash[HEX_HASH_LENGTH  + 1];
    if (get_head_hash(commit_hash) == -1) {
        return; // nothing is committed yet
    }
    write_to_file(path, commit_hash, HEX_HASH_LENGTH);
}


int commit_branch(const char * message) {
    if (message == NULL || strlen(message) == 0) {
        fprintf(stderr, "Commit message is NULL in commit_branch: %s\n", strerror(errno));
        abort();
        return -1;
    }
    char head_hex_hash[HEX_HASH_LENGTH + 1];
    char tree_hash[SHA_DIGEST_LENGTH + 1];
    char tree_hex_hash[HEX_HASH_LENGTH + 1];

    
    if (get_head_hash(head_hex_hash) == 1) { // DETACHED HEAD
        fprintf(stderr, "HEAD is detached, cannot commit\n");
        return -1;
    }
    char head_branch_path[100];
    get_head_branch_path(head_branch_path); 
    
    char commit_hash[HEX_HASH_LENGTH + 1];
    vector parents;

    init_vector(&parents, 2, sizeof(unsigned char[HEX_HASH_LENGTH + 1]) );
    if (strlen(head_hex_hash) == 40) {
        push_back(&parents, head_hex_hash);
    }
    create_tree(tree_hash, ".");
    hash_to_hex(tree_hash, tree_hex_hash);

    if (create_commit(commit_hash, tree_hex_hash, &parents, message) == -1) {
        return -1; // cannot create commit
    }

    write_to_file(head_branch_path, commit_hash, HEX_HASH_LENGTH);

    free_vector(&parents);
    return 0;
}


void get_current_paths(char * path, vector * path_list) {
 if (path == NULL || path_list == NULL) {
        fprintf(stderr, "Invalid arguments to get_paths: %s\n", strerror(errno));
        abort();
        return;
    }
    
    DIR *dir = opendir(path);
    if (!dir) {
        fprintf(stderr, "Failed to open root dir in get_paths: %s\n", strerror(errno));
        abort();
        return;
    }

    struct dirent *entry = NULL;
    while ((entry = readdir(dir))) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0 ||
            strcmp(entry->d_name, ".guts") == 0 || strcmp(entry->d_name, "guts") == 0)
            continue;

        char entry_path[PATH_LENGTH];
        snprintf(entry_path, sizeof(entry_path), "%s/%s", path, entry->d_name);
        
        struct stat st;
        if (lstat(entry_path, &st) == -1){
        
            fprintf(stderr, "lstat failed for <%s>: %s\n", entry_path, strerror(errno));
            abort();
            return;
        }

        int mode = 0;
        if (S_ISREG(st.st_mode))
            mode = (st.st_mode & 0111) ? 0100755 : 0100644;
        else if (S_ISLNK(st.st_mode))
            mode = 0120000;
        else if (S_ISDIR(st.st_mode))
            mode = 040000;
        else{
            fprintf(stderr,"invalid mode: %d %s", st.st_mode, strerror(errno));
            abort();
            return;
        }
        
        if (mode == 040000) { // if dir
            get_current_paths(entry_path, path_list);
        }
        else { // if file
            File_metadata data;
            strcpy(data.path, entry_path);
            create_blob(data.sha1_hash, entry_path);
            push_back(path_list, &data);
        }
    }
}


void get_target_paths(char * tree_hex_hash, char * path, vector * path_list) {
    Object tree_obj;
    init_object(&tree_obj, TREE);
    read_object(&tree_obj, tree_hex_hash);
    decompress_object(&tree_obj);
    vector tree;
    init_vector(&tree, 10, sizeof(Tree_entry));
    parse_tree(&tree_obj, &tree);
    free_object(&tree_obj);

    for (int i = 0; i < tree.size; i++) {
        Tree_entry *entry = get_item(&tree, i);
        char new_path[PATH_LENGTH];
        snprintf(new_path, sizeof(new_path), "%s/%s", path, entry->name);
        if (entry->mode == 040000) { // if dir
            char entry_hex_hash[HEX_HASH_LENGTH + 1];
            hash_to_hex(entry->sha1_hash, entry_hex_hash);
            get_target_paths(entry_hex_hash, new_path, path_list);
        }
        else { // if file
            File_metadata data;
            strcpy(data.path, new_path);
            memcpy(data.sha1_hash, entry->sha1_hash, SHA_DIGEST_LENGTH + 1);
            push_back(path_list, &data);
        }
    }
}

void make_file(const char * path, const unsigned char * sha_hash) {
    if (path == NULL || sha_hash == NULL) {
        fprintf(stderr, "Path or SHA hash is NULL in make_file: %s\n", strerror(errno));
        abort();
        return;
    }

    Object obj;
    init_object(&obj, BLOB);
    char hex_hash[HEX_HASH_LENGTH + 1];
    hash_to_hex(sha_hash, hex_hash);
    read_object(&obj, hex_hash);
    decompress_object(&obj);
    extact_content(&obj);
    FILE *file = fd_open(path, "w");
    if (file == NULL) {
        fprintf(stderr, "Failed to open file %s for writing: %s\n", path, strerror(errno));
        free_object(&obj);
        abort();
        return;
    }
    if (fwrite(obj.content, 1, obj.content_size, file) != obj.content_size) {
        fprintf(stderr, "Failed to write to file %s: %s\n", path, strerror(errno));
        fclose(file);
        free_object(&obj);
        abort();
        return;
    }
    fclose(file);
    free_object(&obj);
}

int commit_tree_hash(const char * commit_hex_hash, char * tree_hex_hash){
    if (commit_hex_hash == NULL || strlen(commit_hex_hash) != HEX_HASH_LENGTH || tree_hex_hash == NULL) {
        fprintf(stderr, "Invalid commit hash or tree hex hash pointer is NULL in commit_tree_hash: %s\n", strerror(errno));
        abort();
        return -1;
    }
    Object commit_obj;
    init_object(&commit_obj, COMMIT);
    if (read_object(&commit_obj, commit_hex_hash) == -1) {
        puts("Invalid commit hash");
        return -1;
    }
    decompress_object(&commit_obj);
    get_tree_hash(&commit_obj, tree_hex_hash);
    free_object(&commit_obj);
}

void load_tree(char * tree_hex_hash){
    if (tree_hex_hash == NULL || strlen(tree_hex_hash) != HEX_HASH_LENGTH) {
        fprintf(stderr, "Invalid tree hash in load_tree: %s\n", strerror(errno));
        abort();
        return;
    }
    // get current state of the dir
    vector current_map;
    init_vector(&current_map, 10, sizeof(File_metadata));
    get_current_paths(".", &current_map);


    // get target state of the dir
    vector target_map;
    init_vector(&target_map, 10, sizeof(File_metadata));
    get_target_paths(tree_hex_hash, ".", &target_map);
    
    sort_vector(&current_map, file_metadata_cmp);
    sort_vector(&target_map, file_metadata_cmp);

    // remove files that are in current but not in target
    for (int i = 0; i < current_map.size; i++) {
        File_metadata *current_file = get_item(&current_map, i);
        File_metadata * found = find_vector(&target_map, current_file, file_metadata_cmp);

        if (found == NULL) {
            // file is in current but not in target, so delete it
            if (remove(current_file->path) == -1) {
                fprintf(stderr, "Failed to remove file %s: %s\n", current_file->path, strerror(errno));
                abort();
            }
        }
    }

    // add files that are in target but not in current
    for (int i = 0; i < target_map.size; i++) {
        File_metadata *target_file = get_item(&target_map, i);
        File_metadata * found = find_vector(&current_map, target_file, file_metadata_cmp);
        if (found == NULL || memcmp(found->sha1_hash, target_file->sha1_hash, SHA_DIGEST_LENGTH) != 0) {
            make_file(target_file->path, target_file->sha1_hash);
        }
    }

    free_vector(&current_map);
    free_vector(&target_map);
}


int load_commit(const char * const commit_hex_hash) {
    if (commit_hex_hash == NULL || strlen(commit_hex_hash) != HEX_HASH_LENGTH) {
        fprintf(stderr, "Invalid commit hash\n");
        return -1;
    }
    // if hash is invalid it must not abort but says invalid hash
    char tree_hex_hash[HEX_HASH_LENGTH + 1];
    commit_tree_hash(commit_hex_hash, tree_hex_hash);

    load_tree(tree_hex_hash);
    return 0;
}


void load_branch(const char * const branch_name) {
    if (branch_name == NULL || strlen(branch_name) == 0) {
        fprintf(stderr, "Invalid branch name\n");
        return;
    }
    char path[PATH_LENGTH];
    strcpy(path , ".guts/refs/heads/");
    strcpy(path + strlen(path), branch_name);
    

    char commit_hex_hash[HEX_HASH_LENGTH + 1];
    FILE *branchFile = fopen(path, "r");
    if (branchFile == NULL) { 
        fprintf(stderr, "Branch %s does not exist\n", branch_name);
        return;
    }
    size_t size = get_file_size(branchFile);

    if (fread(commit_hex_hash, 1, size, branchFile) < size) {
        fprintf(stderr, "Failed to read commit hash from branch file %s: %s\n", path, strerror(errno));
        fclose(branchFile);
        return;
    }
    commit_hex_hash[HEX_HASH_LENGTH] = '\0';
    fclose(branchFile);

    if (strlen(commit_hex_hash) != HEX_HASH_LENGTH) {
        fprintf(stderr, "Nothing committed to Branch: %s", branch_name);
    }

    load_commit(commit_hex_hash);
    // Update the HEAD to point to this branch
    char content[100];
    snprintf(content, sizeof(content), "ref: refs/heads/%s", branch_name);   
    write_to_file(".guts/HEAD", content, strlen(content));
    printf("Switched to branch '%s'\n", branch_name); 
}

int merge_tree(const char * const current_tree_hex_hash, const char * const target_tree_hex_hash, char * new_tree_sha) {
    if (current_tree_hex_hash == NULL || target_tree_hex_hash == NULL || new_tree_sha == NULL) {
        fprintf(stderr, "Invalid arguments to merge_tree: %s\n", strerror(errno));
        abort();
        return -1;
    }
    Object current_tree_obj;
    Object target_tree_obj;
    init_object(&current_tree_obj, TREE);
    init_object(&target_tree_obj, TREE);

    read_object(&current_tree_obj, current_tree_hex_hash);
    decompress_object(&current_tree_obj);
    read_object(&target_tree_obj, target_tree_hex_hash);
    decompress_object(&target_tree_obj);

    vector current_entries;
    vector target_entries;
    init_vector(&current_entries, 10, sizeof(Tree_entry));
    init_vector(&target_entries, 10, sizeof(Tree_entry));

    parse_tree(&current_tree_obj, &current_entries);
    parse_tree(&target_tree_obj, &target_entries);


    free_object(&current_tree_obj);
    free_object(&target_tree_obj);  

    sort_vector(&current_entries, tree_entry_cmp);
    sort_vector(&target_entries, tree_entry_cmp);

    vector merged_entries;
    init_vector(&merged_entries, 10, sizeof(Tree_entry));


    for (int i = 0; i < current_entries.size; i++) {
        Tree_entry *entry = get_item(&current_entries, i);
        Tree_entry *found = find_vector(&target_entries, entry, tree_entry_cmp);
        if (found == NULL || memcmp(found->sha1_hash, entry->sha1_hash, SHA_DIGEST_LENGTH) == 0) {
            push_back(&merged_entries, entry);
        }
    }
    
    for (int i = 0; i < target_entries.size; i++) {
        Tree_entry *entry = get_item(&target_entries, i);
        Tree_entry *found = find_vector(&current_entries, entry, tree_entry_cmp);
        if (found == NULL) {
            push_back(&merged_entries, entry);
        }
        else if (memcmp(found->sha1_hash, entry->sha1_hash, SHA_DIGEST_LENGTH) != 0) {
            if (entry->mode == 040000) {
                char next_current_tree_hex_hash[HEX_HASH_LENGTH + 1];
                char next_target_tree_hex_hash[HEX_HASH_LENGTH + 1];
                char next_new_tree_sha[SHA_DIGEST_LENGTH + 1];
                hash_to_hex(entry->sha1_hash, next_target_tree_hex_hash);
                hash_to_hex(found->sha1_hash, next_current_tree_hex_hash);
                
                merge_tree(next_current_tree_hex_hash, next_target_tree_hex_hash, next_new_tree_sha);
                
                Tree_entry new_entry;
                new_entry.mode = entry->mode;
                strcpy(new_entry.name, entry->name);
                memcpy(new_entry.sha1_hash, next_new_tree_sha, SHA_DIGEST_LENGTH + 1);
                push_back(&merged_entries, &new_entry);
            }
            else {
                push_back(&merged_entries, entry);
            }
        }
    }

    // Create the new tree object
    Object new_tree_obj;
    init_object(&new_tree_obj, TREE);
    
    create_tree_payload(&new_tree_obj, &merged_entries);

    create_object(&new_tree_obj);
    
    compute_sha1_hash(&new_tree_obj);
    
    memcpy(new_tree_sha, new_tree_obj.sha1_hash, SHA_DIGEST_LENGTH + 1);

    compress_blob(&new_tree_obj);
    
    write_object(&new_tree_obj);

    free_object(&new_tree_obj);

    free_vector(&current_entries);
    free_vector(&target_entries);
    free_vector(&merged_entries);    
}

int merge_branch(const char * const branch_name) {
    if (branch_name == NULL || strlen(branch_name) == 0) {
        fprintf(stderr, "Invalid branch name\n");
        return -1;
    }
    // Check if HEAD is detached
    char current_hex_hash[HEX_HASH_LENGTH + 1];
    int x = get_head_hash(current_hex_hash);
    if (x == 1) {
        fprintf(stderr, "HEAD is detached, cannot merge\n");
        return -1;
    }
    else if (x == -1) {
        fprintf(stderr, "Nothing committed to current branch\n");
        return -1;
    }
    if (strlen(current_hex_hash) != HEX_HASH_LENGTH) {
        fprintf(stderr, "Nothing committed to current branch\n");
        return -1;
    }
    char current_branch_name[MAX_ENTRY_NAME_LENGTH];
    if (get_head_branch_name(current_branch_name) == -1) {
        fprintf(stderr, "HEAD is detached, cannot merge\n");
        return -1;
    }
    if (strcmp(current_branch_name, branch_name) == 0) {
        fprintf(stderr, "Cannot merge branch with itself\n");
        return -1;
    }
    
    // Get the target branch's commit hash
    char target_hex_hash[HEX_HASH_LENGTH + 1];
    char target_branch_path[PATH_LENGTH];
    strcpy(target_branch_path, ".guts/refs/heads/");
    strcpy(target_branch_path + strlen(target_branch_path), branch_name);
    FILE *branchFile = fopen(target_branch_path, "r");
    if (branchFile == NULL) {
        fprintf(stderr, "Branch %s does not exist\n", branch_name);
        return -1;
    }
    size_t size = get_file_size(branchFile);
    if (size != HEX_HASH_LENGTH) {
        fprintf(stderr, "Nothing committed to Target branch\n");
        fclose(branchFile);
        return -1;
    }
    if (fread(target_hex_hash, 1, size, branchFile) < size) {
        fprintf(stderr, "Failed to read commit hash from branch file %s: %s", target_branch_path, strerror(errno));
        fclose(branchFile);
        abort();
        return -1;
    }
    target_hex_hash[size] = '\0';
    fclose(branchFile);

    if (strcmp(current_hex_hash, target_hex_hash) == 0) {
        printf("Already on same commit\n");
        return -1; // No need to merge if already on the same commit
    }

    // get the tree hash of the current branch
    char current_tree_hex_hash[HEX_HASH_LENGTH + 1];
    char target_tree_hex_hash[HEX_HASH_LENGTH + 1];
    if (commit_tree_hash(current_hex_hash, current_tree_hex_hash) == -1 ||
        commit_tree_hash(target_hex_hash, target_tree_hex_hash) == -1) {
        return -1;
    }
    char new_tree_sha[SHA_DIGEST_LENGTH + 1];
    char new_tree_hex_hash[HEX_HASH_LENGTH + 1];
    if (memcmp(current_tree_hex_hash, target_tree_hex_hash, HEX_HASH_LENGTH) == 0) {
        memcpy(new_tree_hex_hash, current_tree_hex_hash , HEX_HASH_LENGTH + 1);
    }
    else {
        merge_tree(current_tree_hex_hash, target_tree_hex_hash, new_tree_sha);
        hash_to_hex(new_tree_sha, new_tree_hex_hash);
    }
    // printf("target Tree: %s\n", target_tree_hex_hash);
    // printf("current Tree: %s\n", current_tree_hex_hash);
    // printf("new Tree: %s\n", new_tree_hex_hash);
    vector parents;
    init_vector(&parents, 2, sizeof(unsigned char[HEX_HASH_LENGTH + 1]));
    push_back(&parents, current_hex_hash);
    push_back(&parents, target_hex_hash);

    char commit_hex_hash[HEX_HASH_LENGTH + 1];
    char *message = xmalloc(strlen(branch_name) + 15 + strlen(current_branch_name));
    
    load_tree(new_tree_hex_hash);
    
    sprintf(message, "%s Merged into %s", branch_name, current_branch_name);
    if (create_commit(commit_hex_hash, new_tree_hex_hash, &parents, message) == -1) {
        free(message);
        free_vector(&parents);
        fprintf(stderr, "Failed to create commit during merge\n");
        return -1;
    }
    
    free_vector(&parents);
    
    printf("%s\n", message);
    free(message);
    char current_branch_path[PATH_LENGTH];
    strcpy(current_branch_path, ".guts/refs/heads/");
    strcpy(current_branch_path + strlen(current_branch_path), current_branch_name);
    write_to_file(current_branch_path, commit_hex_hash, HEX_HASH_LENGTH);   
}

int main(int argc, char *argv[]) {
    // Disable output buffering
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    if (argc < 2) {
        fprintf(stderr, "Usage: ./main <command> [<args>]\n");
        return 1;
    }
    
    const char *command = argv[1];
    
    if (strcmp(command, "init") == 0) {
        // You can use print statements as follows for debugging, they'll be visible when running tests.

        if (mkdir(".guts", 0755) == -1 || 
            mkdir(".guts/objects", 0755) == -1 || 
            mkdir(".guts/refs", 0755) == -1 ||
            mkdir(".guts/refs/heads", 0755) == -1 ) {
            fprintf(stderr, "Failed to create directories: %s\n", strerror(errno));
            return 1;
        }
        
        FILE *headFile = fopen(".guts/HEAD", "w");
        if (headFile == NULL) {
            fprintf(stderr, "Failed to create .guts/HEAD file: %s\n", strerror(errno));
            return 1;
        }

        FILE *mainbranch = fopen(".guts/refs/heads/main", "w");
        if (headFile == NULL) {
            fprintf(stderr, "Failed to create .guts/refs/heads/main file: %s\n", strerror(errno));
            return 1;
        }
        fclose(mainbranch);

        fprintf(headFile, "ref: refs/heads/main");
        fclose(headFile);
        
        printf("Initialized git directory\n");
    }
    else if (strcmp(command, "checkout") == 0) {
        if (argc != 3) {
            fprintf(stderr, "Usage: ./main checkout <commit_hash>\n");
            return 1;
        }
        if (load_commit(argv[2]) == 0){
            write_to_file(".guts/HEAD", argv[2], HEX_HASH_LENGTH);
        }
    }
    else if (strcmp(command, "branch") == 0) {
        if (argc != 3 || strlen(argv[2]) == 0) {
            fprintf(stderr, "Usage: ./main branch <name>\n");
            return 1;            
        }
        create_branch(argv[2]);
    }
    else if (strcmp(command, "switch") == 0) {
        if (argc != 3 || strlen(argv[2]) == 0) {
            fprintf(stderr, "Usage: ./main branch <name>\n");
            return 1;            
        }
        load_branch(argv[2]);
    }
    else if (strcmp(command, "set-user") == 0) {
        if (argc != 4) {
            fprintf(stderr, "Usage: ./main set-user <name> <email>\n");
            return 1;
        }

        FILE* file = fopen(".guts/guts", "w");
        if (file == NULL ) {
            fprintf(stderr, "Failed to open guts file: %s\n", strerror(errno));
        }
        size_t name_len = strlen(argv[2]);
        size_t email_len = strlen(argv[3]);
        size_t size = name_len + email_len + 4; // name + email + '\n'
        char *content = xmalloc(size);
        strcpy(content, argv[2]);
        content[name_len] = ' '; // add newline after name
        content[name_len + 1] = '<'; // null-terminate the name
        strcpy(content + name_len + 2, argv[3]);
        content[name_len + email_len + 2] = '>';
        content[size-1] = '\0';
        if (fwrite(content, 1, size, file) != size) {
            fprintf(stderr, "Failed to write to guts file: %s\n", strerror(errno));
            fclose(file);
            free(content);
            return 1;
        }
        fclose(file);
        free(content);
        printf("User set: %s <%s>\n", argv[2], argv[3]);
    }
    else if (strcmp(command, "cat-file") == 0) {
        if (argc != 4) {
            fprintf(stderr, "Usage: ./main cat-file -[pc] <hash>\n");
            return 1;
        }
        Object obj;
        init_object(&obj,BLOB);
        read_object(&obj, argv[3]);
        
        // Decompress the data
        long decompressed_size = decompress_object(&obj);


        // for (int i = 0; i < stream.total_out; i++) {
        //     printf("%02x " , decompressed[i]);
        // }
        // printf("\n");
        // for (int i = 0; i < stream.total_out; i++) {
        //     printf("%c" , decompressed[i]);
        // }
        // Print decompressed content after the header (e.g., "blob 12\0...")
        if (strcmp(argv[2] , "-c") == 0) {
            Commit_entry * commit = parse_commit(&obj);
            display_commit_entry(commit);
            free_commit_entry(commit);
        }
        else{  
            unsigned char *content = memchr(obj.uncompressed_data, 0, obj.uncompressed_size); // find \0
            if (!content) {
                fprintf(stderr, "Invalid object format: %s\n", strerror(errno));
                free_object(&obj);
                abort();
                return 1;
            }
            content++; // start after the null terminator
            fwrite(content, 1, obj.uncompressed_data + obj.uncompressed_size - content , stdout);
        }
        free_object(&obj);
    }

    else if (strcmp(command, "hash-object") == 0) {
        if (argc != 4 || strcmp(argv[2], "-w") != 0) {
            fprintf(stderr, "Usage: ./your_program.sh hash-object -w <filename>\n");
            return 1;
        }

        unsigned char tree_hash_rlt[SHA_DIGEST_LENGTH];
        create_blob(tree_hash_rlt, argv[3]);
        for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
            printf("%02x", tree_hash_rlt[i]);
        }
        printf("\n");
    }
    else if (strcmp(command, "ls-tree") == 0) {
        if (argc != 3) {
            fprintf(stderr, "Usage: ./main ls-tree <hash>\n");
            return 1;
        }
        
        Object obj;
        init_object(&obj, TREE);

        // Initialize the object with the provided hash
        memcpy(obj.hex_hash, argv[2], SHA_DIGEST_LENGTH * 2);
        obj.hex_hash[SHA_DIGEST_LENGTH * 2] = '\0';
        // read the content of the tree object
        create_dir_path(&obj);create_path(&obj);
        
        FILE *file;
        if ((file = fopen(obj.path, "rb")) == NULL) {
            fprintf(stderr, "Failed to open object file: %s\n", strerror(errno));
            free_object(&obj);
            return 1;
        }
        // Get file size
        obj.compressed_size = get_file_size(file);

        // Read the file content
        obj.compressed_data = xmalloc(obj.compressed_size);


        if (fread(obj.compressed_data, 1, obj.compressed_size, file) != obj.compressed_size) {
            fprintf(stderr, "Failed to read object file: %s\n", strerror(errno));
            fclose(file);
            free_object(&obj);
            abort();
            return 1;
        }
        fclose(file);
        // uncompress the data
        long decompressed_size = decompress_object(&obj);
        // parse the content and save the data

        // display
        vector tree;
        init_vector(&tree, 10, sizeof(Tree_entry));
        parse_tree(&obj, &tree);
        for (int i = 0; i < tree.size; i++)
            display_tree_entry((Tree_entry *)get_item(&tree,i));

        free_vector(&tree);
        free_object(&obj);
    }
    else if (strcmp(command, "write-tree") == 0) {
        unsigned char tree_hash_rlt[SHA_DIGEST_LENGTH];
        char path[PATH_LENGTH];
        if (argc == 3) {
            strcpy(path, argv[2]);
        }
        else if (argc == 2) {
            strcpy(path, ".");
        }
        else {
            fprintf(stderr, "Usage: ./main write-tree [<path>]\n");
            return 1;
        }
        printf("Creating tree for path: %s\n", path);
        // Create the tree object
        create_tree(tree_hash_rlt, path);
        for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
            printf("%02x", tree_hash_rlt[i]);
        }
        printf("\n");
    }
    else if (strcmp(command, "commit-tree") == 0) {
        if (argc < 5 || strcmp(argv[argc - 2], "-m") != 0) {
            fprintf(stderr, "Usage: ./main commit-tree <tree_hash> [<parent_hash> ...] -m <message>\n");
            return 1;
        }

        vector parents;
        init_vector(&parents, 10, sizeof(unsigned char[HEX_HASH_LENGTH + 1]));
        
        // Collect parent hashes
        for (int i = 4; i < argc - 2; i++) {
            unsigned char parent_hash[HEX_HASH_LENGTH + 1];
            memcpy(parent_hash, argv[i], HEX_HASH_LENGTH);
            parent_hash[HEX_HASH_LENGTH] = '\0';
            push_back(&parents, parent_hash);
        }

        // Create the commit
        unsigned char commit_hex_hash[HEX_HASH_LENGTH + 1];
        if (create_commit(commit_hex_hash, argv[2], &parents, argv[argc - 1]) != 0) {
            fprintf(stderr, "Failed to create commit\n");
            free_vector(&parents);
            return 1;
        }
        puts("Commit created successfully");
        printf("Commit Hash: %s\n" , commit_hex_hash);

        free_vector(&parents);
    }
    else if (strcmp(command, "commit") == 0) {
        if (argc != 3) {
            fprintf(stderr, "Usage: ./main commit <message>\n");
            return 1;
        }
        if (commit_branch(argv[2]) == 0) {
            puts("Changes committed successfully");
        }
        else {
            fprintf(stderr, "Failed to commit changes\n");
            return 1;
        }
    }
    else if (strcmp(command, "log") == 0) {
        char head_hash[HEX_HASH_LENGTH + 1];
        int ans = get_head_hash(head_hash);
        if (ans == -1) {
            fprintf(stderr, "Nothing committed yet\n");
            return 1;
        }
        else if (ans == 1) {
            puts("DETACHED HEAD");
        }
        else {
            char name[100];
            get_head_branch_name(name);
            printf("HEAD: %s\n", name);
        }
        display_log(head_hash);
    }
    else if (strcmp(command, "merge") == 0) {
        if (argc != 3) {
            fprintf(stderr, "Usage: ./main merge <branch_name>\n");
            return 1;
        }
        merge_branch(argv[2]);
    }
    else {
        fprintf(stderr, "Unknown command %s\n", command);
        return 1;
    }
    
    return 0;
}

/*
internal commands
- cat-file -c <hash> -- display commit details
- cat-file -p <hash> -- display content of a blob
- hash-object -w <filename> -- create a blob object for the file
- ls-tree <hash> -- list the contents of a tree object
- write-tree [<path>] -- create a tree object for the current directory or specified path
- commit-tree <tree_hash> [<parent_hash> ...] -m <message>

external commands
- init
- checkout <hash> -- load commit with hash
- branch <name> -- create a branch
- switch <name> -- switch to a branch
- set-user <name> <email> -- set user name and email
- commit <message> -- commit changes in the current branch
- log -- display commit history
- merge <branch_name> -- merge a branch into the current branch
*/