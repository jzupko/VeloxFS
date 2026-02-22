/*
 * veloxvault.c — GTK3 GUI file vault using veloxfs.h
 *
 * A single-file GUI application that stores all data inside one opaque
 * .vfs image file using veloxfs.h directly — no FUSE, no kernel involvement,
 * no root permissions required.
 *
 * FEATURES:
 *   - Create / open / close vault images (.vfs)
 *   - Browse files and folders with sidebar tree + content list
 *   - Create folders, import files, export files, delete, rename
 *   - Drag-and-drop import from the host file manager
 *   - Storage usage bar
 *   - Chunked I/O — large files (100MB+) import/export without loading
 *     the entire file into RAM at once
 *
 * COMPILE:
 *   gcc -Wall -O2 veloxvault.c -o veloxvault \
 *       `pkg-config gtk+-3.0 --cflags --libs`
 *
 * USAGE:
 *   ./veloxvault
 *   ./veloxvault path/to/existing.vfs
 *
 * ENCRYPTION NOTE:
 *   The I/O callbacks (vault_read_cb / vault_write_cb) are the single point
 *   where encryption can be layered in.  Wrap them with AES-256-XTS or
 *   ChaCha20 and veloxfs never sees plaintext.  The vault file is opaque
 *   to anyone without the key regardless.
 *
 * LICENSE: Public domain or MIT (same as veloxfs.h)
 */

#define veloxfs_IMPLEMENTATION
#include "veloxfs.h"

#include <gtk/gtk.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include <time.h>

/* =========================================================================
 * Column indices — content list store
 * ======================================================================= */
enum {
    CC_IS_DIR = 0,   /* gboolean — used for sort-dirs-first */
    CC_ICON,         /* gchararray — icon name string        */
    CC_NAME,         /* gchararray                           */
    CC_SIZE,         /* gchararray — human-readable          */
    CC_MODIFIED,     /* gchararray — human-readable          */
    CC_FULL_PATH,    /* gchararray — full veloxfs path       */
    CC_N
};

/* Column indices — sidebar tree store */
enum {
    SC_ICON = 0,     /* gchararray */
    SC_NAME,         /* gchararray */
    SC_PATH,         /* gchararray — full veloxfs path */
    SC_N
};

/* =========================================================================
 * Global state
 * ======================================================================= */

static struct {
    veloxfs_handle  fs;
    int             disk_fd;
    int             mounted;
    char            vault_path[4096];
    char            current_path[veloxfs_MAX_PATH];
} g_vault = { .disk_fd = -1 };

static struct {
    GtkWidget    *window;
    GtkWidget    *header_bar;
    GtkWidget    *stack;           /* "welcome" vs "browser"  */
    GtkWidget    *toolbar;
    GtkWidget    *paned;
    GtkWidget    *sidebar;         /* GtkTreeView             */
    GtkWidget    *content;         /* GtkTreeView             */
    GtkWidget    *path_label;
    GtkWidget    *status_label;
    GtkWidget    *usage_bar;
    GtkTreeStore *sidebar_store;
    GtkListStore *content_store;
    /* toolbar buttons that require an open vault */
    GtkWidget    *btn_up;
    GtkWidget    *btn_new_folder;
    GtkWidget    *btn_import;
    GtkWidget    *btn_export;
    GtkWidget    *btn_delete;
    GtkWidget    *btn_rename;
    GtkWidget    *btn_close_vault;
} g_ui;

/* =========================================================================
 * Forward declarations
 * ======================================================================= */
static void refresh_content(const char *path);
static void refresh_sidebar(void);
static void refresh_status(void);
static void ui_vault_opened(void);
static void ui_vault_closed(void);

/* =========================================================================
 * I/O callbacks — pread/pwrite are atomic w.r.t. file position
 * ======================================================================= */

static int vault_read_cb(void *user, uint64_t off, void *buf, uint32_t n) {
    return pread(*(int *)user, buf, n, (off_t)off) == (ssize_t)n ? 0 : -1;
}
static int vault_write_cb(void *user, uint64_t off, const void *buf, uint32_t n) {
    return pwrite(*(int *)user, buf, n, (off_t)off) == (ssize_t)n ? 0 : -1;
}

/* =========================================================================
 * Vault lifecycle
 * ======================================================================= */

static int vault_open(const char *path) {
    int fd = open(path, O_RDWR);
    if (fd < 0) return -1;

    g_vault.disk_fd = fd;
    veloxfs_io io = { vault_read_cb, vault_write_cb, malloc, calloc, free, &g_vault.disk_fd };

    if (veloxfs_mount(&g_vault.fs, io) != veloxfs_OK) {
        close(fd);
        g_vault.disk_fd = -1;
        return -1;
    }

    g_vault.mounted = 1;
    strncpy(g_vault.vault_path, path, sizeof(g_vault.vault_path) - 1);
    strncpy(g_vault.current_path, "/", sizeof(g_vault.current_path) - 1);
    return 0;
}

static int vault_create(const char *path, uint64_t size_mb) {
    int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return -1;

    if (ftruncate(fd, (off_t)(size_mb * 1024 * 1024)) != 0) {
        close(fd); unlink(path); return -1;
    }

    veloxfs_io io   = { vault_read_cb, vault_write_cb, malloc, calloc, free, &fd };
    uint64_t blocks = (size_mb * 1024 * 1024) / veloxfs_BLOCK_SIZE;
    int ret = veloxfs_format(io, blocks, 1 /* journaling */);
    close(fd);

    if (ret != veloxfs_OK) { unlink(path); return -1; }
    return vault_open(path);
}

static void vault_close(void) {
    if (!g_vault.mounted) return;
    veloxfs_sync(&g_vault.fs);
    fsync(g_vault.disk_fd);
    veloxfs_unmount(&g_vault.fs);
    close(g_vault.disk_fd);
    g_vault.disk_fd = -1;
    g_vault.mounted = 0;
    strncpy(g_vault.current_path, "/", sizeof(g_vault.current_path) - 1);
}

/* =========================================================================
 * Path helpers
 * ======================================================================= */

static void path_join(char *out, size_t sz, const char *parent, const char *name) {
    if (strcmp(parent, "/") == 0)
        snprintf(out, sz, "/%s", name);
    else
        snprintf(out, sz, "%s/%s", parent, name);
}

static void path_parent(const char *path, char *out, size_t sz) {
    const char *last = strrchr(path, '/');
    if (!last || last == path) { strncpy(out, "/", sz); return; }
    size_t len = (size_t)(last - path);
    if (len >= sz) len = sz - 1;
    memcpy(out, path, len);
    out[len] = '\0';
}

/* =========================================================================
 * Directory listing
 * ======================================================================= */

typedef struct {
    char            name[veloxfs_MAX_PATH];
    int             is_dir;
    veloxfs_stat_t  stat;
} VaultEntry;

typedef struct {
    VaultEntry *entries;
    int         count, cap;
    const char *parent;
    size_t      parent_len;
    /* dedup set for subdirectory names — 256 entries, 256-char name max */
    char        seen[256][256];
    int         seen_count;
} ListCtx;

static int lctx_seen(ListCtx *c, const char *n) {
    for (int i = 0; i < c->seen_count; i++)
        if (strcmp(c->seen[i], n) == 0) return 1;
    return 0;
}
static void lctx_mark(ListCtx *c, const char *n) {
    if (c->seen_count < 256)
        strncpy(c->seen[c->seen_count++], n, 255);
}
static void lctx_push(ListCtx *c, const char *name, int is_dir,
                      const veloxfs_stat_t *st) {
    if (c->count >= c->cap) {
        c->cap = c->cap ? c->cap * 2 : 16;
        c->entries = realloc(c->entries, (size_t)c->cap * sizeof(VaultEntry));
    }
    VaultEntry *e = &c->entries[c->count++];
    strncpy(e->name, name, veloxfs_MAX_PATH - 1);
    e->name[veloxfs_MAX_PATH - 1] = '\0';
    e->is_dir = is_dir;
    e->stat   = st ? *st : (veloxfs_stat_t){0};
}

static void list_cb(const char *path, const veloxfs_stat_t *st,
                    int isd, void *u) {
    ListCtx *c = (ListCtx *)u;
    (void)isd;

    const char *rel;
    if (strcmp(c->parent, "/") == 0) {
        if (path[0] != '/') return;
        rel = path + 1;
    } else {
        if (strncmp(path, c->parent, c->parent_len) != 0) return;
        rel = path + c->parent_len;
        if (*rel != '/') return;
        rel++;
    }
    if (!*rel) return;

    const char *slash = strchr(rel, '/');
    if (slash) {
        /* path belongs to a subdirectory — emit the dir name once */
        size_t len = (size_t)(slash - rel);
        if (!len || len >= veloxfs_MAX_PATH) return;
        char dn[veloxfs_MAX_PATH];
        memcpy(dn, rel, len); dn[len] = '\0';
        if (lctx_seen(c, dn)) return;
        lctx_mark(c, dn);
        lctx_push(c, dn, 1, NULL);
    } else {
        /* direct file child */
        if (strcmp(rel, ".veloxfs_dir") == 0) return;
        lctx_push(c, rel, 0, st);
    }
}

static int entry_cmp(const void *a, const void *b) {
    const VaultEntry *ea = a, *eb = b;
    if (ea->is_dir != eb->is_dir) return eb->is_dir - ea->is_dir; /* dirs first */
    return strcmp(ea->name, eb->name);
}

/* =========================================================================
 * Formatting helpers
 * ======================================================================= */

static const char *fmt_size(uint64_t b) {
    /* Rotating pool: safe to call multiple times in one snprintf expression */
    static char pool[4][32];
    static int  idx = 0;
    char *buf = pool[idx++ & 3];
    if      (b < 1024ULL)           snprintf(buf, 32, "%lu B",   (unsigned long)b);
    else if (b < 1024ULL * 1024)    snprintf(buf, 32, "%.1f KB", b / 1024.0);
    else if (b < 1024ULL*1024*1024) snprintf(buf, 32, "%.1f MB", b / (1024.0*1024));
    else                            snprintf(buf, 32, "%.2f GB", b / (1024.0*1024*1024));
    return buf;
}

static const char *fmt_date(uint64_t ts) {
    static char buf[32];
    if (!ts) { strcpy(buf, "—"); return buf; }
    time_t t = (time_t)ts;
    struct tm *tm = localtime(&t);
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M", tm);
    return buf;
}

static const char *file_icon(const char *name) {
    const char *e = strrchr(name, '.');
    if (!e) return "text-x-generic";
    e++;
    if (!strcasecmp(e,"png")||!strcasecmp(e,"jpg")||!strcasecmp(e,"jpeg")||
        !strcasecmp(e,"gif")||!strcasecmp(e,"webp")||!strcasecmp(e,"bmp")||
        !strcasecmp(e,"svg")) return "image-x-generic";
    if (!strcasecmp(e,"mp3")||!strcasecmp(e,"wav")||!strcasecmp(e,"flac")||
        !strcasecmp(e,"ogg")||!strcasecmp(e,"aac")) return "audio-x-generic";
    if (!strcasecmp(e,"mp4")||!strcasecmp(e,"mkv")||!strcasecmp(e,"avi")||
        !strcasecmp(e,"mov")||!strcasecmp(e,"webm")) return "video-x-generic";
    if (!strcasecmp(e,"pdf")) return "application-pdf";
    if (!strcasecmp(e,"zip")||!strcasecmp(e,"tar")||!strcasecmp(e,"gz")||
        !strcasecmp(e,"7z")||!strcasecmp(e,"rar")||!strcasecmp(e,"bz2"))
        return "package-x-generic";
    if (!strcasecmp(e,"c")||!strcasecmp(e,"h")||!strcasecmp(e,"cpp")||
        !strcasecmp(e,"py")||!strcasecmp(e,"js")||!strcasecmp(e,"sh"))
        return "text-x-script";
    return "text-x-generic";
}

/* =========================================================================
 * Low-level vault file operations (used by callbacks below)
 * ======================================================================= */

/* Import a host file into the vault at vault_dest, using chunked I/O. */
static int vault_import_file(const char *host_path, const char *vault_dest) {
    FILE *f = fopen(host_path, "rb");
    if (!f) return -1;

    /* Delete any existing file at the destination */
    veloxfs_delete(&g_vault.fs, vault_dest);

    if (veloxfs_create(&g_vault.fs, vault_dest, 0644) != veloxfs_OK) {
        fclose(f); return -1;
    }

    veloxfs_file vf;
    if (veloxfs_open(&g_vault.fs, vault_dest, veloxfs_O_WRONLY, &vf) != veloxfs_OK) {
        fclose(f); return -1;
    }

    char *buf = malloc(256 * 1024); /* 256 KB chunks */
    if (!buf) { veloxfs_close(&vf); fclose(f); return -1; }

    int ok = 1;
    size_t n;
    while ((n = fread(buf, 1, 256 * 1024, f)) > 0) {
        if (veloxfs_write(&vf, buf, (uint64_t)n) != veloxfs_OK) { ok = 0; break; }
    }

    free(buf);
    veloxfs_close(&vf);
    fclose(f);
    return ok ? 0 : -1;
}

/* Export a vault file to a host path, using chunked I/O. */
static int vault_export_file(const char *vault_src, const char *host_path) {
    veloxfs_stat_t st;
    if (veloxfs_stat(&g_vault.fs, vault_src, &st) != veloxfs_OK) return -1;

    veloxfs_file vf;
    if (veloxfs_open(&g_vault.fs, vault_src, veloxfs_O_RDONLY, &vf) != veloxfs_OK) return -1;

    FILE *f = fopen(host_path, "wb");
    if (!f) { veloxfs_close(&vf); return -1; }

    char *buf = malloc(256 * 1024);
    if (!buf) { fclose(f); veloxfs_close(&vf); return -1; }

    int ok = 1;
    uint64_t left = st.size;
    while (left > 0) {
        uint64_t want = left < 256*1024 ? left : 256*1024;
        uint64_t got  = 0;
        if (veloxfs_read(&vf, buf, want, &got) != veloxfs_OK || !got) { ok = 0; break; }
        fwrite(buf, 1, (size_t)got, f);
        left -= got;
        /*
         * veloxfs_read advances current_block only when the read loop exits
         * with remaining > 0.  When a read ends exactly on a 4096-byte block
         * boundary (remaining == 0), the block pointer is left pointing at the
         * block we just finished.  The next call would re-read that same block,
         * silently producing garbage output.
         *
         * Fix: if we landed on a block boundary and there is still data left,
         * call veloxfs_seek to the current position.  seek re-navigates the
         * FAT chain from scratch, leaving current_block pointing at the correct
         * next block.
         */
        if (left > 0 && (vf.position % veloxfs_BLOCK_SIZE) == 0) {
            veloxfs_seek(&vf, (int64_t)vf.position, 0 /* SEEK_SET */);
        }
    }

    free(buf);
    fclose(f);
    veloxfs_close(&vf);
    return ok ? 0 : -1;
}

/* Delete all veloxfs entries whose path starts with "path/" */
static void vault_delete_recursive(const char *path) {
    char prefix[veloxfs_MAX_PATH];
    snprintf(prefix, sizeof(prefix), "%s/", path);
    size_t plen = strlen(prefix);

    char (*to_del)[veloxfs_MAX_PATH] = NULL;
    int ndel = 0, cap = 0;

    for (uint64_t i = 0; i < g_vault.fs.num_dirents; i++) {
        if (g_vault.fs.directory[i].inode_num == 0) continue;
        if (strncmp(g_vault.fs.directory[i].path, prefix, plen) != 0) continue;
        if (ndel >= cap) {
            cap = cap ? cap * 2 : 16;
            to_del = realloc(to_del, (size_t)cap * veloxfs_MAX_PATH);
        }
        strncpy(to_del[ndel++], g_vault.fs.directory[i].path, veloxfs_MAX_PATH - 1);
    }

    for (int i = 0; i < ndel; i++)
        veloxfs_delete(&g_vault.fs, to_del[i]);
    free(to_del);
}

/* Rename every entry under old_path/ to new_path/ */
static void vault_rename_dir(const char *old_path, const char *new_path) {
    char prefix[veloxfs_MAX_PATH];
    snprintf(prefix, sizeof(prefix), "%s/", old_path);
    size_t plen = strlen(prefix);

    /* Collect first, then rename — avoids iterator invalidation */
    char (*old_ent)[veloxfs_MAX_PATH] = NULL;
    char (*new_ent)[veloxfs_MAX_PATH] = NULL;
    int n = 0, cap = 0;

    for (uint64_t i = 0; i < g_vault.fs.num_dirents; i++) {
        if (g_vault.fs.directory[i].inode_num == 0) continue;
        const char *p = g_vault.fs.directory[i].path;
        if (strncmp(p, prefix, plen) != 0) continue;
        if (n >= cap) {
            cap = cap ? cap * 2 : 16;
            old_ent = realloc(old_ent, (size_t)cap * veloxfs_MAX_PATH);
            new_ent = realloc(new_ent, (size_t)cap * veloxfs_MAX_PATH);
        }
        strncpy(old_ent[n], p, veloxfs_MAX_PATH - 1);
        snprintf(new_ent[n], veloxfs_MAX_PATH, "%s/%s", new_path, p + plen);
        n++;
    }

    for (int i = 0; i < n; i++)
        veloxfs_rename(&g_vault.fs, old_ent[i], new_ent[i]);

    free(old_ent);
    free(new_ent);
}

/* =========================================================================
 * UI refresh
 * ======================================================================= */

static void sidebar_populate_node(GtkTreeIter *parent, const char *path) {
    ListCtx c = { .parent = path, .parent_len = strlen(path) };
    veloxfs_list(&g_vault.fs, path, list_cb, &c);
    qsort(c.entries, (size_t)c.count, sizeof(VaultEntry), entry_cmp);

    for (int i = 0; i < c.count; i++) {
        if (!c.entries[i].is_dir) continue;
        char child[veloxfs_MAX_PATH];
        path_join(child, sizeof(child), path, c.entries[i].name);

        GtkTreeIter iter;
        gtk_tree_store_append(g_ui.sidebar_store, &iter, parent);
        gtk_tree_store_set(g_ui.sidebar_store, &iter,
            SC_ICON, "folder",
            SC_NAME, c.entries[i].name,
            SC_PATH, child,
            -1);
        sidebar_populate_node(&iter, child);
    }
    free(c.entries);
}

static void refresh_sidebar(void) {
    gtk_tree_store_clear(g_ui.sidebar_store);
    if (!g_vault.mounted) return;

    GtkTreeIter root;
    gtk_tree_store_append(g_ui.sidebar_store, &root, NULL);
    gtk_tree_store_set(g_ui.sidebar_store, &root,
        SC_ICON, "drive-harddisk",
        SC_NAME, "Vault",
        SC_PATH, "/",
        -1);
    sidebar_populate_node(&root, "/");
    gtk_tree_view_expand_all(GTK_TREE_VIEW(g_ui.sidebar));
}

static void refresh_content(const char *path) {
    strncpy(g_vault.current_path, path, veloxfs_MAX_PATH - 1);
    gtk_list_store_clear(g_ui.content_store);
    if (!g_vault.mounted) return;

    ListCtx c = { .parent = path, .parent_len = strlen(path) };
    veloxfs_list(&g_vault.fs, path, list_cb, &c);
    qsort(c.entries, (size_t)c.count, sizeof(VaultEntry), entry_cmp);

    for (int i = 0; i < c.count; i++) {
        char full[veloxfs_MAX_PATH];
        path_join(full, sizeof(full), path, c.entries[i].name);

        GtkTreeIter iter;
        gtk_list_store_append(g_ui.content_store, &iter);
        gtk_list_store_set(g_ui.content_store, &iter,
            CC_IS_DIR,   (gboolean)c.entries[i].is_dir,
            CC_ICON,     c.entries[i].is_dir ? "folder"
                                             : file_icon(c.entries[i].name),
            CC_NAME,     c.entries[i].name,
            CC_SIZE,     c.entries[i].is_dir ? "—"
                                             : fmt_size(c.entries[i].stat.size),
            CC_MODIFIED, c.entries[i].is_dir ? "—"
                                             : fmt_date(c.entries[i].stat.mtime),
            CC_FULL_PATH, full,
            -1);
    }
    free(c.entries);

    gtk_label_set_text(GTK_LABEL(g_ui.path_label), path);
    gtk_widget_set_sensitive(g_ui.btn_up, strcmp(path, "/") != 0);
    /* deselect — export/delete/rename require selection */
    gtk_tree_selection_unselect_all(
        gtk_tree_view_get_selection(GTK_TREE_VIEW(g_ui.content)));

    refresh_status();
}

static void refresh_status(void) {
    if (!g_vault.mounted) {
        gtk_label_set_text(GTK_LABEL(g_ui.status_label), "No vault open");
        gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(g_ui.usage_bar), 0.0);
        return;
    }
    uint64_t total, used, free_b;
    veloxfs_statfs(&g_vault.fs, &total, &used, &free_b);
    uint64_t used_b  = used  * veloxfs_BLOCK_SIZE;
    uint64_t total_b = total * veloxfs_BLOCK_SIZE;

    char msg[128];
    snprintf(msg, sizeof(msg), "%s used of %s  (%lu files)",
             fmt_size(used_b), fmt_size(total_b),
             (unsigned long)g_vault.fs.num_dirents); /* rough count */
    gtk_label_set_text(GTK_LABEL(g_ui.status_label), msg);
    gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(g_ui.usage_bar),
        total > 0 ? (double)used / (double)total : 0.0);
}

/* =========================================================================
 * UI state helpers
 * ======================================================================= */

static void ui_vault_opened(void) {
    const char *base = strrchr(g_vault.vault_path, '/');
    gtk_header_bar_set_subtitle(GTK_HEADER_BAR(g_ui.header_bar),
        base ? base + 1 : g_vault.vault_path);

    gtk_widget_set_sensitive(g_ui.btn_new_folder,   TRUE);
    gtk_widget_set_sensitive(g_ui.btn_import,        TRUE);
    gtk_widget_set_sensitive(g_ui.btn_export,        FALSE);
    gtk_widget_set_sensitive(g_ui.btn_delete,        FALSE);
    gtk_widget_set_sensitive(g_ui.btn_rename,        FALSE);
    gtk_widget_set_sensitive(g_ui.btn_close_vault,   TRUE);
    gtk_widget_set_sensitive(g_ui.btn_up,            FALSE);

    gtk_stack_set_visible_child_name(GTK_STACK(g_ui.stack), "browser");
    refresh_sidebar();
    refresh_content("/");
}

static void ui_vault_closed(void) {
    gtk_header_bar_set_subtitle(GTK_HEADER_BAR(g_ui.header_bar),
        "No vault open");
    gtk_widget_set_sensitive(g_ui.btn_new_folder,   FALSE);
    gtk_widget_set_sensitive(g_ui.btn_import,        FALSE);
    gtk_widget_set_sensitive(g_ui.btn_export,        FALSE);
    gtk_widget_set_sensitive(g_ui.btn_delete,        FALSE);
    gtk_widget_set_sensitive(g_ui.btn_rename,        FALSE);
    gtk_widget_set_sensitive(g_ui.btn_close_vault,   FALSE);
    gtk_widget_set_sensitive(g_ui.btn_up,            FALSE);
    gtk_tree_store_clear(g_ui.sidebar_store);
    gtk_list_store_clear(g_ui.content_store);
    gtk_label_set_text(GTK_LABEL(g_ui.path_label), "/");
    refresh_status();
    gtk_stack_set_visible_child_name(GTK_STACK(g_ui.stack), "welcome");
}

static void show_error(const char *msg) {
    GtkWidget *d = gtk_message_dialog_new(GTK_WINDOW(g_ui.window),
        GTK_DIALOG_MODAL, GTK_MESSAGE_ERROR, GTK_BUTTONS_OK, "%s", msg);
    gtk_dialog_run(GTK_DIALOG(d));
    gtk_widget_destroy(d);
}

/* =========================================================================
 * File operation callbacks
 * ======================================================================= */

static void on_selection_changed(GtkTreeSelection *sel, gpointer data) {
    (void)data;
    gboolean has = gtk_tree_selection_count_selected_rows(sel) > 0;
    gtk_widget_set_sensitive(g_ui.btn_export, has);
    gtk_widget_set_sensitive(g_ui.btn_delete, has);
    gtk_widget_set_sensitive(g_ui.btn_rename, has);
}

/* Helper: get selected entry from content view */
static gboolean get_selected(gboolean *is_dir_out, gchar **name_out,
                              gchar **full_path_out) {
    GtkTreeSelection *sel =
        gtk_tree_view_get_selection(GTK_TREE_VIEW(g_ui.content));
    GtkTreeModel *model;
    GtkTreeIter   iter;
    if (!gtk_tree_selection_get_selected(sel, &model, &iter)) return FALSE;
    gtk_tree_model_get(model, &iter,
        CC_IS_DIR,    is_dir_out,
        CC_NAME,      name_out,
        CC_FULL_PATH, full_path_out,
        -1);
    return TRUE;
}

static void on_new_folder_clicked(GtkWidget *w, gpointer data) {
    (void)w; (void)data;

    GtkWidget *dlg = gtk_dialog_new_with_buttons("New Folder",
        GTK_WINDOW(g_ui.window),
        GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
        "_Cancel", GTK_RESPONSE_CANCEL,
        "_Create", GTK_RESPONSE_ACCEPT, NULL);
    gtk_dialog_set_default_response(GTK_DIALOG(dlg), GTK_RESPONSE_ACCEPT);

    GtkWidget *box    = gtk_dialog_get_content_area(GTK_DIALOG(dlg));
    GtkWidget *label  = gtk_label_new("Folder name:");
    GtkWidget *entry  = gtk_entry_new();
    gtk_entry_set_text(GTK_ENTRY(entry), "New Folder");
    gtk_entry_set_activates_default(GTK_ENTRY(entry), TRUE);
    gtk_widget_set_margin_start(entry,  12); gtk_widget_set_margin_end(entry,  12);
    gtk_widget_set_margin_top(entry,     4); gtk_widget_set_margin_bottom(entry, 12);
    gtk_widget_set_margin_start(label,  12);
    gtk_widget_set_margin_top(label,    12);
    gtk_container_add(GTK_CONTAINER(box), label);
    gtk_container_add(GTK_CONTAINER(box), entry);
    gtk_widget_show_all(dlg);

    if (gtk_dialog_run(GTK_DIALOG(dlg)) == GTK_RESPONSE_ACCEPT) {
        const char *fname = gtk_entry_get_text(GTK_ENTRY(entry));
        if (fname && *fname) {
            char folder[veloxfs_MAX_PATH], marker[veloxfs_MAX_PATH];
            path_join(folder, sizeof(folder), g_vault.current_path, fname);
            snprintf(marker, sizeof(marker), "%s/.veloxfs_dir", folder);

            if (veloxfs_create(&g_vault.fs, marker, 0644) == veloxfs_OK) {
                veloxfs_sync(&g_vault.fs);
                fsync(g_vault.disk_fd);
                refresh_content(g_vault.current_path);
                refresh_sidebar();
            } else {
                show_error("Could not create folder (name conflict or vault full).");
            }
        }
    }
    gtk_widget_destroy(dlg);
}

/* Shared import logic — used by button and drag-drop */
static void do_import_files(GSList *host_paths) {
    int errors = 0;
    for (GSList *l = host_paths; l; l = l->next) {
        const char *hp = (const char *)l->data;
        const char *base = strrchr(hp, '/');
        base = base ? base + 1 : hp;

        char dest[veloxfs_MAX_PATH];
        path_join(dest, sizeof(dest), g_vault.current_path, base);

        if (vault_import_file(hp, dest) != 0) errors++;
    }
    if (errors)
        show_error("One or more files could not be imported\n"
                   "(vault may be full or a name conflict exists).");

    veloxfs_sync(&g_vault.fs);
    fsync(g_vault.disk_fd);
    refresh_content(g_vault.current_path);
    refresh_sidebar();
}

static void on_import_clicked(GtkWidget *w, gpointer data) {
    (void)w; (void)data;

    GtkWidget *dlg = gtk_file_chooser_dialog_new("Import Files",
        GTK_WINDOW(g_ui.window), GTK_FILE_CHOOSER_ACTION_OPEN,
        "_Cancel", GTK_RESPONSE_CANCEL,
        "_Import", GTK_RESPONSE_ACCEPT, NULL);
    gtk_file_chooser_set_select_multiple(GTK_FILE_CHOOSER(dlg), TRUE);

    if (gtk_dialog_run(GTK_DIALOG(dlg)) == GTK_RESPONSE_ACCEPT) {
        GSList *files = gtk_file_chooser_get_filenames(GTK_FILE_CHOOSER(dlg));
        do_import_files(files);
        g_slist_free_full(files, g_free);
    }
    gtk_widget_destroy(dlg);
}

static void on_export_clicked(GtkWidget *w, gpointer data) {
    (void)w; (void)data;

    gboolean is_dir; gchar *name = NULL, *full = NULL;
    if (!get_selected(&is_dir, &name, &full)) goto cleanup;

    if (is_dir) {
        show_error("Select a file to export — folder export is not supported.");
        goto cleanup;
    }

    GtkWidget *dlg = gtk_file_chooser_dialog_new("Export File",
        GTK_WINDOW(g_ui.window), GTK_FILE_CHOOSER_ACTION_SAVE,
        "_Cancel", GTK_RESPONSE_CANCEL,
        "_Save",   GTK_RESPONSE_ACCEPT, NULL);
    gtk_file_chooser_set_do_overwrite_confirmation(GTK_FILE_CHOOSER(dlg), TRUE);
    gtk_file_chooser_set_current_name(GTK_FILE_CHOOSER(dlg), name);

    if (gtk_dialog_run(GTK_DIALOG(dlg)) == GTK_RESPONSE_ACCEPT) {
        gchar *save = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dlg));
        if (vault_export_file(full, save) != 0)
            show_error("Export failed.");
        g_free(save);
    }
    gtk_widget_destroy(dlg);

cleanup:
    g_free(name); g_free(full);
}

static void on_delete_clicked(GtkWidget *w, gpointer data) {
    (void)w; (void)data;

    gboolean is_dir; gchar *name = NULL, *full = NULL;
    if (!get_selected(&is_dir, &name, &full)) goto cleanup;

    GtkWidget *dlg = gtk_message_dialog_new(GTK_WINDOW(g_ui.window),
        GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
        GTK_MESSAGE_QUESTION, GTK_BUTTONS_YES_NO,
        is_dir ? "Delete folder \"%s\" and all its contents?"
               : "Delete \"%s\"?", name);

    if (gtk_dialog_run(GTK_DIALOG(dlg)) == GTK_RESPONSE_YES) {
        if (is_dir)
            vault_delete_recursive(full);
        else
            veloxfs_delete(&g_vault.fs, full);

        veloxfs_sync(&g_vault.fs);
        fsync(g_vault.disk_fd);
        refresh_content(g_vault.current_path);
        refresh_sidebar();
    }
    gtk_widget_destroy(dlg);

cleanup:
    g_free(name); g_free(full);
}

static void on_rename_clicked(GtkWidget *w, gpointer data) {
    (void)w; (void)data;

    gboolean is_dir; gchar *name = NULL, *full = NULL;
    if (!get_selected(&is_dir, &name, &full)) goto cleanup;

    GtkWidget *dlg = gtk_dialog_new_with_buttons("Rename",
        GTK_WINDOW(g_ui.window),
        GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
        "_Cancel", GTK_RESPONSE_CANCEL,
        "_Rename", GTK_RESPONSE_ACCEPT, NULL);
    gtk_dialog_set_default_response(GTK_DIALOG(dlg), GTK_RESPONSE_ACCEPT);

    GtkWidget *box   = gtk_dialog_get_content_area(GTK_DIALOG(dlg));
    GtkWidget *entry = gtk_entry_new();
    gtk_entry_set_text(GTK_ENTRY(entry), name);
    gtk_entry_set_activates_default(GTK_ENTRY(entry), TRUE);
    gtk_widget_set_margin_start(entry,  12); gtk_widget_set_margin_end(entry,  12);
    gtk_widget_set_margin_top(entry,    12); gtk_widget_set_margin_bottom(entry, 12);
    gtk_container_add(GTK_CONTAINER(box), entry);
    gtk_widget_show_all(dlg);

    if (gtk_dialog_run(GTK_DIALOG(dlg)) == GTK_RESPONSE_ACCEPT) {
        const char *new_name = gtk_entry_get_text(GTK_ENTRY(entry));
        if (new_name && *new_name && strcmp(new_name, name) != 0) {
            char new_path[veloxfs_MAX_PATH];
            path_join(new_path, sizeof(new_path), g_vault.current_path, new_name);

            if (is_dir)
                vault_rename_dir(full, new_path);
            else
                veloxfs_rename(&g_vault.fs, full, new_path);

            veloxfs_sync(&g_vault.fs);
            fsync(g_vault.disk_fd);
            refresh_content(g_vault.current_path);
            refresh_sidebar();
        }
    }
    gtk_widget_destroy(dlg);

cleanup:
    g_free(name); g_free(full);
}

/* =========================================================================
 * Navigation callbacks
 * ======================================================================= */

static void on_content_row_activated(GtkTreeView *tv, GtkTreePath *tp,
                                     GtkTreeViewColumn *col, gpointer data) {
    (void)col; (void)data;
    GtkTreeModel *model = gtk_tree_view_get_model(tv);
    GtkTreeIter   iter;
    if (!gtk_tree_model_get_iter(model, &iter, tp)) return;

    gboolean is_dir; gchar *full = NULL;
    gtk_tree_model_get(model, &iter, CC_IS_DIR, &is_dir, CC_FULL_PATH, &full, -1);
    if (is_dir) refresh_content(full);
    g_free(full);
}

static void on_sidebar_row_activated(GtkTreeView *tv, GtkTreePath *tp,
                                     GtkTreeViewColumn *col, gpointer data) {
    (void)col; (void)data;
    GtkTreeModel *model = gtk_tree_view_get_model(tv);
    GtkTreeIter   iter;
    if (!gtk_tree_model_get_iter(model, &iter, tp)) return;

    gchar *path = NULL;
    gtk_tree_model_get(model, &iter, SC_PATH, &path, -1);
    if (path) refresh_content(path);
    g_free(path);
}

static void on_up_clicked(GtkWidget *w, gpointer data) {
    (void)w; (void)data;
    if (strcmp(g_vault.current_path, "/") == 0) return;
    char parent[veloxfs_MAX_PATH];
    path_parent(g_vault.current_path, parent, sizeof(parent));
    refresh_content(parent);
}

/* =========================================================================
 * Drag-and-drop import from host file manager
 * ======================================================================= */

static void on_drag_data_received(GtkWidget *widget, GdkDragContext *ctx,
                                   gint x, gint y, GtkSelectionData *sel_data,
                                   guint info, guint time, gpointer user_data) {
    (void)widget; (void)x; (void)y; (void)info; (void)user_data;

    if (!g_vault.mounted) { gtk_drag_finish(ctx, FALSE, FALSE, time); return; }

    gchar **uris = gtk_selection_data_get_uris(sel_data);
    if (!uris) { gtk_drag_finish(ctx, FALSE, FALSE, time); return; }

    GSList *paths = NULL;
    for (int i = 0; uris[i]; i++) {
        gchar *p = g_filename_from_uri(uris[i], NULL, NULL);
        if (p) paths = g_slist_append(paths, p);
    }
    g_strfreev(uris);

    do_import_files(paths);
    g_slist_free_full(paths, g_free);
    gtk_drag_finish(ctx, TRUE, FALSE, time);
}

/* =========================================================================
 * Vault management callbacks
 * ======================================================================= */

static void on_new_vault_clicked(GtkWidget *w, gpointer data) {
    (void)w; (void)data;

    GtkWidget *dlg = gtk_file_chooser_dialog_new("Create New Vault",
        GTK_WINDOW(g_ui.window), GTK_FILE_CHOOSER_ACTION_SAVE,
        "_Cancel", GTK_RESPONSE_CANCEL,
        "_Create", GTK_RESPONSE_ACCEPT, NULL);
    gtk_file_chooser_set_do_overwrite_confirmation(GTK_FILE_CHOOSER(dlg), TRUE);
    gtk_file_chooser_set_current_name(GTK_FILE_CHOOSER(dlg), "vault.vfs");

    /* Size selector embedded in the chooser */
    GtkWidget *hbox  = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *lbl   = gtk_label_new("Vault size (MB):");
    GtkWidget *spin  = gtk_spin_button_new_with_range(64, 102400, 64);
    gtk_spin_button_set_value(GTK_SPIN_BUTTON(spin), 512);
    gtk_box_pack_start(GTK_BOX(hbox), lbl,  FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(hbox), spin, FALSE, FALSE, 0);
    gtk_widget_show_all(hbox);
    gtk_file_chooser_set_extra_widget(GTK_FILE_CHOOSER(dlg), hbox);

    if (gtk_dialog_run(GTK_DIALOG(dlg)) == GTK_RESPONSE_ACCEPT) {
        gchar *path   = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dlg));
        int    size   = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(spin));

        if (g_vault.mounted) { vault_close(); ui_vault_closed(); }

        if (vault_create(path, (uint64_t)size) == 0) {
            ui_vault_opened();
        } else {
            char msg[512];
            snprintf(msg, sizeof(msg), "Failed to create vault:\n%s\n\n"
                     "Check that you have write permission and enough disk space.", path);
            show_error(msg);
        }
        g_free(path);
    }
    gtk_widget_destroy(dlg);
}

static void on_open_vault_clicked(GtkWidget *w, gpointer data) {
    (void)w; (void)data;

    GtkWidget *dlg = gtk_file_chooser_dialog_new("Open Vault",
        GTK_WINDOW(g_ui.window), GTK_FILE_CHOOSER_ACTION_OPEN,
        "_Cancel", GTK_RESPONSE_CANCEL,
        "_Open",   GTK_RESPONSE_ACCEPT, NULL);

    GtkFileFilter *ff = gtk_file_filter_new();
    gtk_file_filter_set_name(ff, "VeloxFS Vault (*.vfs)");
    gtk_file_filter_add_pattern(ff, "*.vfs");
    gtk_file_chooser_add_filter(GTK_FILE_CHOOSER(dlg), ff);

    GtkFileFilter *fa = gtk_file_filter_new();
    gtk_file_filter_set_name(fa, "All files");
    gtk_file_filter_add_pattern(fa, "*");
    gtk_file_chooser_add_filter(GTK_FILE_CHOOSER(dlg), fa);

    if (gtk_dialog_run(GTK_DIALOG(dlg)) == GTK_RESPONSE_ACCEPT) {
        gchar *path = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dlg));

        if (g_vault.mounted) { vault_close(); ui_vault_closed(); }

        if (vault_open(path) == 0) {
            veloxfs_fsck(&g_vault.fs); /* repair orphaned blocks on open */
            ui_vault_opened();
        } else {
            char msg[512];
            snprintf(msg, sizeof(msg),
                     "Failed to open vault:\n%s\n\n"
                     "The file may not be a valid veloxfs image.", path);
            show_error(msg);
        }
        g_free(path);
    }
    gtk_widget_destroy(dlg);
}

static void on_close_vault_clicked(GtkWidget *w, gpointer data) {
    (void)w; (void)data;
    vault_close();
    ui_vault_closed();
}

static gboolean on_window_delete(GtkWidget *w, GdkEvent *e, gpointer d) {
    (void)w; (void)e; (void)d;
    vault_close();
    return FALSE; /* allow close */
}

/* =========================================================================
 * UI construction
 * ======================================================================= */

static GtkWidget *make_tb_button(const char *icon, const char *tooltip) {
    GtkWidget *btn = gtk_button_new_from_icon_name(icon, GTK_ICON_SIZE_SMALL_TOOLBAR);
    gtk_button_set_relief(GTK_BUTTON(btn), GTK_RELIEF_NONE);
    gtk_widget_set_tooltip_text(btn, tooltip);
    gtk_widget_set_sensitive(btn, FALSE);
    return btn;
}

static GtkWidget *build_welcome_page(void) {
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 24);
    gtk_widget_set_halign(box, GTK_ALIGN_CENTER);
    gtk_widget_set_valign(box, GTK_ALIGN_CENTER);
    gtk_widget_set_margin_bottom(box, 60);

    GtkWidget *icon = gtk_image_new_from_icon_name("drive-harddisk",
                                                   GTK_ICON_SIZE_DIALOG);
    gtk_image_set_pixel_size(GTK_IMAGE(icon), 96);

    GtkWidget *title = gtk_label_new("VeloxVault");
    PangoAttrList *al = pango_attr_list_new();
    pango_attr_list_insert(al, pango_attr_scale_new(2.0));
    pango_attr_list_insert(al, pango_attr_weight_new(PANGO_WEIGHT_BOLD));
    gtk_label_set_attributes(GTK_LABEL(title), al);
    pango_attr_list_unref(al);

    GtkWidget *sub = gtk_label_new("Create or open a vault to get started");
    gtk_style_context_add_class(gtk_widget_get_style_context(sub), "dim-label");

    GtkWidget *btn_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
    gtk_widget_set_halign(btn_box, GTK_ALIGN_CENTER);

    GtkWidget *btn_new  = gtk_button_new_with_label("  New Vault  ");
    GtkWidget *btn_open = gtk_button_new_with_label("  Open Vault  ");
    gtk_style_context_add_class(gtk_widget_get_style_context(btn_new),
                                "suggested-action");
    g_signal_connect(btn_new,  "clicked", G_CALLBACK(on_new_vault_clicked),  NULL);
    g_signal_connect(btn_open, "clicked", G_CALLBACK(on_open_vault_clicked), NULL);

    gtk_box_pack_start(GTK_BOX(btn_box), btn_new,  FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(btn_box), btn_open, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box), icon,    FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box), title,   FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box), sub,     FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box), btn_box, FALSE, FALSE, 0);

    return box;
}

static GtkWidget *build_browser_page(void) {
    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);

    /* ---- Toolbar ---- */
    GtkWidget *tb = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 4);
    gtk_widget_set_margin_start(tb,  6);
    gtk_widget_set_margin_end(tb,    6);
    gtk_widget_set_margin_top(tb,    4);
    gtk_widget_set_margin_bottom(tb, 4);

    g_ui.btn_up         = make_tb_button("go-up",          "Go up");
    g_ui.btn_new_folder = make_tb_button("folder-new",     "New Folder");
    g_ui.btn_import     = make_tb_button("document-open",  "Import Files");
    g_ui.btn_export     = make_tb_button("document-save",  "Export Selected");
    g_ui.btn_delete     = make_tb_button("edit-delete",    "Delete Selected");
    g_ui.btn_rename     = make_tb_button("document-edit",  "Rename Selected");
    g_ui.btn_close_vault= make_tb_button("drive-removable-media", "Close Vault");

    g_signal_connect(g_ui.btn_up,          "clicked", G_CALLBACK(on_up_clicked),          NULL);
    g_signal_connect(g_ui.btn_new_folder,  "clicked", G_CALLBACK(on_new_folder_clicked),  NULL);
    g_signal_connect(g_ui.btn_import,      "clicked", G_CALLBACK(on_import_clicked),       NULL);
    g_signal_connect(g_ui.btn_export,      "clicked", G_CALLBACK(on_export_clicked),       NULL);
    g_signal_connect(g_ui.btn_delete,      "clicked", G_CALLBACK(on_delete_clicked),       NULL);
    g_signal_connect(g_ui.btn_rename,      "clicked", G_CALLBACK(on_rename_clicked),       NULL);
    g_signal_connect(g_ui.btn_close_vault, "clicked", G_CALLBACK(on_close_vault_clicked),  NULL);

    gtk_box_pack_start(GTK_BOX(tb), g_ui.btn_up,          FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(tb), gtk_separator_new(GTK_ORIENTATION_VERTICAL), FALSE, FALSE, 2);
    gtk_box_pack_start(GTK_BOX(tb), g_ui.btn_new_folder,  FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(tb), g_ui.btn_import,      FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(tb), g_ui.btn_export,      FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(tb), g_ui.btn_delete,      FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(tb), g_ui.btn_rename,      FALSE, FALSE, 0);

    /* Path label */
    g_ui.path_label = gtk_label_new("/");
    gtk_widget_set_margin_start(g_ui.path_label, 8);
    gtk_label_set_ellipsize(GTK_LABEL(g_ui.path_label), PANGO_ELLIPSIZE_START);
    gtk_style_context_add_class(gtk_widget_get_style_context(g_ui.path_label),
                                "dim-label");
    gtk_box_pack_start(GTK_BOX(tb), g_ui.path_label, TRUE, TRUE, 0);
    gtk_box_pack_end(GTK_BOX(tb), g_ui.btn_close_vault, FALSE, FALSE, 0);
    g_ui.toolbar = tb;

    /* ---- Paned: sidebar + content ---- */
    GtkWidget *paned = gtk_paned_new(GTK_ORIENTATION_HORIZONTAL);
    gtk_paned_set_position(GTK_PANED(paned), 220);
    g_ui.paned = paned;

    /* Sidebar */
    g_ui.sidebar_store = gtk_tree_store_new(SC_N,
        G_TYPE_STRING,  /* SC_ICON  */
        G_TYPE_STRING,  /* SC_NAME  */
        G_TYPE_STRING); /* SC_PATH  */

    GtkWidget *sidebar_sw = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(sidebar_sw),
        GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);

    GtkWidget *sidebar_tv = gtk_tree_view_new_with_model(
        GTK_TREE_MODEL(g_ui.sidebar_store));
    gtk_tree_view_set_headers_visible(GTK_TREE_VIEW(sidebar_tv), FALSE);
    gtk_tree_view_set_activate_on_single_click(GTK_TREE_VIEW(sidebar_tv), TRUE);
    g_ui.sidebar = sidebar_tv;

    GtkCellRenderer    *s_icon = gtk_cell_renderer_pixbuf_new();
    GtkCellRenderer    *s_text = gtk_cell_renderer_text_new();
    GtkTreeViewColumn  *s_col  = gtk_tree_view_column_new();
    gtk_tree_view_column_pack_start(s_col, s_icon, FALSE);
    gtk_tree_view_column_pack_start(s_col, s_text, TRUE);
    gtk_tree_view_column_add_attribute(s_col, s_icon, "icon-name", SC_ICON);
    gtk_tree_view_column_add_attribute(s_col, s_text, "text",      SC_NAME);
    gtk_tree_view_append_column(GTK_TREE_VIEW(sidebar_tv), s_col);
    g_signal_connect(sidebar_tv, "row-activated",
                     G_CALLBACK(on_sidebar_row_activated), NULL);

    gtk_container_add(GTK_CONTAINER(sidebar_sw), sidebar_tv);
    gtk_paned_pack1(GTK_PANED(paned), sidebar_sw, FALSE, FALSE);

    /* Content list */
    g_ui.content_store = gtk_list_store_new(CC_N,
        G_TYPE_BOOLEAN, /* CC_IS_DIR    */
        G_TYPE_STRING,  /* CC_ICON      */
        G_TYPE_STRING,  /* CC_NAME      */
        G_TYPE_STRING,  /* CC_SIZE      */
        G_TYPE_STRING,  /* CC_MODIFIED  */
        G_TYPE_STRING); /* CC_FULL_PATH */

    /* Sort: directories first, then alpha */
    GtkTreeModel *sorted = gtk_tree_model_sort_new_with_model(
        GTK_TREE_MODEL(g_ui.content_store));
    gtk_tree_sortable_set_sort_column_id(GTK_TREE_SORTABLE(sorted),
        CC_NAME, GTK_SORT_ASCENDING);

    GtkWidget *content_sw = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(content_sw),
        GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);

    GtkWidget *content_tv = gtk_tree_view_new_with_model(sorted);
    gtk_tree_view_set_headers_visible(GTK_TREE_VIEW(content_tv), TRUE);
    g_ui.content = content_tv;

    /* Column: Icon + Name */
    GtkTreeViewColumn *c_name = gtk_tree_view_column_new();
    gtk_tree_view_column_set_title(c_name, "Name");
    gtk_tree_view_column_set_expand(c_name, TRUE);
    gtk_tree_view_column_set_resizable(c_name, TRUE);
    GtkCellRenderer *c_icon = gtk_cell_renderer_pixbuf_new();
    GtkCellRenderer *c_text = gtk_cell_renderer_text_new();
    gtk_tree_view_column_pack_start(c_name, c_icon, FALSE);
    gtk_tree_view_column_pack_start(c_name, c_text, TRUE);
    gtk_tree_view_column_add_attribute(c_name, c_icon, "icon-name", CC_ICON);
    gtk_tree_view_column_add_attribute(c_name, c_text, "text",      CC_NAME);
    gtk_tree_view_append_column(GTK_TREE_VIEW(content_tv), c_name);

    /* Column: Size */
    GtkTreeViewColumn *c_size = gtk_tree_view_column_new_with_attributes(
        "Size", gtk_cell_renderer_text_new(), "text", CC_SIZE, NULL);
    gtk_tree_view_column_set_min_width(c_size, 90);
    gtk_tree_view_column_set_resizable(c_size, TRUE);
    gtk_tree_view_append_column(GTK_TREE_VIEW(content_tv), c_size);

    /* Column: Modified */
    GtkTreeViewColumn *c_mod = gtk_tree_view_column_new_with_attributes(
        "Modified", gtk_cell_renderer_text_new(), "text", CC_MODIFIED, NULL);
    gtk_tree_view_column_set_min_width(c_mod, 130);
    gtk_tree_view_column_set_resizable(c_mod, TRUE);
    gtk_tree_view_append_column(GTK_TREE_VIEW(content_tv), c_mod);

    /* Selection and activation */
    GtkTreeSelection *sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(content_tv));
    gtk_tree_selection_set_mode(sel, GTK_SELECTION_SINGLE);
    g_signal_connect(sel, "changed", G_CALLBACK(on_selection_changed), NULL);
    g_signal_connect(content_tv, "row-activated",
                     G_CALLBACK(on_content_row_activated), NULL);

    /* Drag-and-drop: accept URIs from host file manager */
    static const GtkTargetEntry drop_targets[] = {
        { "text/uri-list", 0, 0 }
    };
    gtk_drag_dest_set(content_tv, GTK_DEST_DEFAULT_ALL,
                      drop_targets, 1, GDK_ACTION_COPY);
    g_signal_connect(content_tv, "drag-data-received",
                     G_CALLBACK(on_drag_data_received), NULL);

    gtk_container_add(GTK_CONTAINER(content_sw), content_tv);
    gtk_paned_pack2(GTK_PANED(paned), content_sw, TRUE, FALSE);

    /* ---- Status bar ---- */
    GtkWidget *sbar = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_widget_set_margin_start(sbar,  8);
    gtk_widget_set_margin_end(sbar,    8);
    gtk_widget_set_margin_top(sbar,    4);
    gtk_widget_set_margin_bottom(sbar, 4);

    g_ui.status_label = gtk_label_new("No vault open");
    gtk_label_set_ellipsize(GTK_LABEL(g_ui.status_label), PANGO_ELLIPSIZE_END);
    gtk_style_context_add_class(gtk_widget_get_style_context(g_ui.status_label),
                                "dim-label");

    g_ui.usage_bar = gtk_progress_bar_new();
    gtk_widget_set_size_request(g_ui.usage_bar, 120, -1);
    gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(g_ui.usage_bar), 0.0);

    gtk_box_pack_start(GTK_BOX(sbar), g_ui.status_label, TRUE,  TRUE,  0);
    gtk_box_pack_start(GTK_BOX(sbar), g_ui.usage_bar,    FALSE, FALSE, 0);

    GtkWidget *sep = gtk_separator_new(GTK_ORIENTATION_HORIZONTAL);

    gtk_box_pack_start(GTK_BOX(vbox), tb,    FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(vbox),
        gtk_separator_new(GTK_ORIENTATION_HORIZONTAL), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(vbox), paned, TRUE,  TRUE,  0);
    gtk_box_pack_start(GTK_BOX(vbox), sep,   FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(vbox), sbar,  FALSE, FALSE, 0);

    return vbox;
}

static void build_main_window(void) {
    g_ui.window = gtk_application_window_new(
        GTK_APPLICATION(g_object_get_data(G_OBJECT(gtk_settings_get_default()),
                                          "app")));

    /* Fall back to a plain window if we can't get the GtkApplication */
    if (!GTK_IS_APPLICATION_WINDOW(g_ui.window)) {
        g_ui.window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    }

    gtk_window_set_default_size(GTK_WINDOW(g_ui.window), 900, 560);
    gtk_window_set_title(GTK_WINDOW(g_ui.window), "VeloxVault");

    /* Header bar */
    g_ui.header_bar = gtk_header_bar_new();
    gtk_header_bar_set_show_close_button(GTK_HEADER_BAR(g_ui.header_bar), TRUE);
    gtk_header_bar_set_title(GTK_HEADER_BAR(g_ui.header_bar), "VeloxVault");
    gtk_header_bar_set_subtitle(GTK_HEADER_BAR(g_ui.header_bar), "No vault open");

    /* Header bar: New / Open buttons always visible */
    GtkWidget *hb_new  = gtk_button_new_with_label("New");
    GtkWidget *hb_open = gtk_button_new_with_label("Open");
    gtk_style_context_add_class(gtk_widget_get_style_context(hb_new),
                                "suggested-action");
    g_signal_connect(hb_new,  "clicked", G_CALLBACK(on_new_vault_clicked),  NULL);
    g_signal_connect(hb_open, "clicked", G_CALLBACK(on_open_vault_clicked), NULL);
    gtk_header_bar_pack_start(GTK_HEADER_BAR(g_ui.header_bar), hb_new);
    gtk_header_bar_pack_start(GTK_HEADER_BAR(g_ui.header_bar), hb_open);

    gtk_window_set_titlebar(GTK_WINDOW(g_ui.window), g_ui.header_bar);

    /* Stack: welcome page / browser page */
    g_ui.stack = gtk_stack_new();
    gtk_stack_set_transition_type(GTK_STACK(g_ui.stack),
                                  GTK_STACK_TRANSITION_TYPE_CROSSFADE);
    gtk_stack_add_named(GTK_STACK(g_ui.stack), build_welcome_page(), "welcome");
    gtk_stack_add_named(GTK_STACK(g_ui.stack), build_browser_page(),  "browser");
    gtk_stack_set_visible_child_name(GTK_STACK(g_ui.stack), "welcome");

    gtk_container_add(GTK_CONTAINER(g_ui.window), g_ui.stack);

    g_signal_connect(g_ui.window, "delete-event",
                     G_CALLBACK(on_window_delete), NULL);

    gtk_widget_show_all(g_ui.window);
    ui_vault_closed(); /* set initial sensitive state */
}

/* =========================================================================
 * Application activate callback
 * ======================================================================= */

static char *g_startup_vault = NULL; /* optional CLI argument */

static void on_activate(GtkApplication *app, gpointer user_data) {
    (void)user_data;
    /* stash app on settings so build_main_window can retrieve it */
    g_object_set_data(G_OBJECT(gtk_settings_get_default()), "app", app);
    build_main_window();

    if (g_startup_vault) {
        if (vault_open(g_startup_vault) == 0) {
            veloxfs_fsck(&g_vault.fs);
            ui_vault_opened();
        } else {
            char msg[512];
            snprintf(msg, sizeof(msg),
                     "Could not open vault:\n%s", g_startup_vault);
            show_error(msg);
        }
    }
}

/* =========================================================================
 * main
 * ======================================================================= */

int main(int argc, char *argv[]) {
    if (argc >= 2 && argv[1][0] != '-')
        g_startup_vault = argv[1];

    GtkApplication *app = gtk_application_new("io.veloxfs.vault",
                                              G_APPLICATION_FLAGS_NONE);
    g_signal_connect(app, "activate", G_CALLBACK(on_activate), NULL);

    /* Strip our argument before passing to GTK */
    int gtk_argc = g_startup_vault ? 1 : argc;
    int status   = g_application_run(G_APPLICATION(app), gtk_argc, argv);

    vault_close();
    g_object_unref(app);
    return status;
}