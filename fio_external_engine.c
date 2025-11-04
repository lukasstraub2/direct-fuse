/*
 * Copied from the fio project
 * engines/skeleton_external.c
 *
 * This file is licenced under GPL v2.0
 */

/*
 * Skeleton for a sample external io engine
 *
 * Should be compiled with:
 *
 * gcc -Wall -O2 -g -D_GNU_SOURCE -include ../config-host.h -shared -rdynamic -fPIC -o skeleton_external.o skeleton_external.c
 * (also requires -D_GNU_SOURCE -DCONFIG_STRSEP on Linux)
 *
 */
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>

#include "config-host.h"
#include "fio.h"
#include "optgroup.h"
#include "sysio.h"

/*
 * The core of the module is identical to the ones included with fio,
 * read those. You cannot use register_ioengine() and unregister_ioengine()
 * for external modules, they should be gotten through dlsym()
 */

/*
 * The io engine can define its own options within the io engine source.
 * The option member must not be at offset 0, due to the way fio parses
 * the given option. Just add a padding pointer unless the io engine has
 * something usable.
 */
struct fio_libsysio_options {
	void *pad;
	char *source;
	char *target;
	char *filesystem;
};

static struct fio_option options[] = {
	{
		.name	= "source",
		.lname	= "mount source",
		.type	= FIO_OPT_STR_STORE,
		.off1	= offsetof(struct fio_libsysio_options, source),
		.help	= "mount source",
		.category = FIO_OPT_C_ENGINE, /* always use this */
		.group	= FIO_OPT_G_INVALID, /* this can be different */
	},
	{
		.name	= "target",
		.lname	= "mount target",
		.type	= FIO_OPT_STR_STORE,
		.off1	= offsetof(struct fio_libsysio_options, target),
		.help	= "mount target",
		.category = FIO_OPT_C_ENGINE, /* always use this */
		.group	= FIO_OPT_G_INVALID, /* this can be different */
	},
	{
		.name	= "filesystem",
		.lname	= "mount filesystem",
		.type	= FIO_OPT_STR_STORE,
		.off1	= offsetof(struct fio_libsysio_options, filesystem),
		.help	= "mount filesystem",
		.category = FIO_OPT_C_ENGINE, /* always use this */
		.group	= FIO_OPT_G_INVALID, /* this can be different */
	},
	{
		.name	= NULL,
	},
};

/*
 * The ->queue() hook is responsible for initiating io on the io_u
 * being passed in. If the io engine is a synchronous one, io may complete
 * before ->queue() returns. Required.
 *
 * The io engine must transfer in the direction noted by io_u->ddir
 * to the buffer pointed to by io_u->xfer_buf for as many bytes as
 * io_u->xfer_buflen. Residual data count may be set in io_u->resid
 * for a short read/write.
 */
static enum fio_q_status libsysio_queue(struct thread_data *td,
					    struct io_u *io_u)
{
	int ret;
	struct fio_file *file = io_u->file;
	/*
	 * Double sanity check to catch errant write on a readonly setup
	 */
	fio_ro_check(td, io_u);

	if (io_u->ddir == DDIR_READ || io_u->ddir == DDIR_WRITE) {
		if (io_u->ddir == DDIR_READ) {
			ret = SYSIO_INTERFACE_NAME(pread)(file->fd, io_u->xfer_buf, io_u->xfer_buflen, io_u->offset);
		} else if (io_u->ddir == DDIR_WRITE) {
			ret = SYSIO_INTERFACE_NAME(pwrite)(file->fd, io_u->xfer_buf, io_u->xfer_buflen, io_u->offset);
		}

		if (ret >= 0) {
			io_u->resid = io_u->xfer_buflen - ret;
			io_u->error = 0;
		}
	} else if (io_u->ddir == DDIR_TRIM) {
		errno = EINVAL;
		ret = -1;
	} else if (io_u->ddir == DDIR_SYNC) {
		ret = SYSIO_INTERFACE_NAME(fsync)(file->fd);
	} else if (io_u->ddir == DDIR_DATASYNC) {
		ret = SYSIO_INTERFACE_NAME(fdatasync)(file->fd);
	} else {
		errno = EINVAL;
		ret = -1;
	}

	if (ret < 0) {
		io_u->error = errno;
		io_u_log_error(td, io_u);
		td_verror(td, errno, "xfer");
	}

	return FIO_Q_COMPLETED;
}

static volatile int sysio_initialized = 0;

/*
 * The init function is called once per thread/process, and should set up
 * any structures that this io engine requires to keep track of io. Not
 * required.
 */
static int libsysio_init(struct thread_data *td)
{
	int ret;
	struct fio_libsysio_options *opt = td->eo;

	dprint(FD_IO, "libsysio_init\n");

	if (!sysio_initialized) {
		sysio_initialized = 1;
		ret = _sysio_all_startup();
		if (ret < 0) {
			log_err("sysio startup failed\n");
			return -1;
		}
	}

	ret = SYSIO_INTERFACE_NAME(mount)(opt->source, opt->target, opt->filesystem, MS_NOSUID, NULL);
	if (ret < 0) {
		log_err("mount(%s, %s, %s) failed\n", opt->source, opt->target, opt->filesystem);
		return -1;
	}

	return 0;
}

/*
 * This is paired with the ->init() function and is called when a thread is
 * done doing io. Should tear down anything setup by the ->init() function.
 * Not required.
 */
static void libsysio_cleanup(struct thread_data *td)
{
	int ret;
	struct fio_libsysio_options *opt = td->eo;

	unsigned long fs_len = strlen(opt->filesystem);
	unsigned long target_len = strlen(opt->target);
	char *path = malloc(fs_len + target_len + 2);
	memcpy(path, opt->filesystem, fs_len);
	path[fs_len] = ':';
	memcpy(path + fs_len + 1, opt->target, target_len);
	path[fs_len + target_len + 1] = 0;

	ret = SYSIO_INTERFACE_NAME(umount)(path);
	if (ret < 0) {
		log_err("umount(%s) failed\n", path);
	}
}

/*
 * Hook for opening the given file. Unless the engine has special
 * needs, it usually just provides generic_open_file() as the handler.
 */
static int libsysio_open(struct thread_data *td, struct fio_file *f)
{
	int flags = 0;

	dprint(FD_FILE, "libsysio open %s\n", f->file_name);

	if (td->o.odirect)
		flags |= O_DIRECT;
	flags |= td->o.sync_io;
	if (td->o.create_on_open && td->o.allow_create)
		flags |= O_CREAT;

	if (td_write(td)) {
		flags |= O_RDWR;

		if (f->filetype == FIO_TYPE_FILE && td->o.allow_create) {
			flags |= O_CREAT;
		}
	} else if (td_read(td)) {
		flags |= O_RDONLY;
	} else {
		flags |= O_RDWR;
	}

	f->fd = SYSIO_INTERFACE_NAME(open)(f->file_name, flags, 0600);
	if (f->fd < 0) {
		td_verror(td, errno, "open()");
		return 1;
	}

	return 0;
}

static int _libsysio_close(struct fio_file *f)
{
	if (f->fd < 0) {
		return 0;
	}

	int ret = SYSIO_INTERFACE_NAME(close)(f->fd);
	if (ret < 0) {
		return errno;
	}
	f->fd = -1;

	return 0;
}

/*
 * Hook for closing a file. See fio_skeleton_open().
 */
static int libsysio_close(struct thread_data *td, struct fio_file *f)
{
	dprint(FD_FILE, "libsysio close %s\n", f->file_name);

	return _libsysio_close(f);
}

static int libsysio_unlink(struct thread_data *td, struct fio_file *f)
{
	int ret;

	dprint(FD_FILE, "libsysio unlink %s\n", f->file_name);

	// libsysio crashes when closing an unlinked file
	ret = _libsysio_close(f);
	if (ret != 0) {
		return ret;
	}

	// fio may unlink the file twice and libsysio crashes when unlinking a nonexisting file
	// also libsysio access() does not work
	if (f->engine_pos) {
		return 0;
	}

	ret = SYSIO_INTERFACE_NAME(unlink)(f->file_name);
	if (ret < 0) {
		return errno;
	}
	f->engine_pos = 1;

	return 0;
}

/*
 * Note that the structure is exported, so that fio can get it via
 * dlsym(..., "ioengine"); for (and only for) external engines.
 */
struct ioengine_ops ioengine = {
	.name			= "libsysio",
	.version		= FIO_IOOPS_VERSION,
	.init			= libsysio_init,
	.queue			= libsysio_queue,
	.cleanup		= libsysio_cleanup,
	.open_file		= libsysio_open,
	.close_file		= libsysio_close,
	.unlink_file 	= libsysio_unlink,
	.options		= options,
	.option_struct_size	= sizeof(struct fio_libsysio_options),
	.flags = FIO_SYNCIO | FIO_DISKLESSIO,
};
