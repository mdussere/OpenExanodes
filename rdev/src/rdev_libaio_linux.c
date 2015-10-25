/*
 * Copyright 2002, 2009 Seanodes Ltd http://www.seanodes.com. All rights
 * reserved and protected by French, UK, U.S. and other countries' copyright laws.
 * This file is part of Exanodes project and is subject to the terms
 * and conditions defined in the LICENSE file which is present in the root
 * directory of the project.
 */

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
# ifndef major
#   include <sys/sysmacros.h>
# endif

#include "common/include/exa_error.h"
#include "os/include/os_mem.h"
#include "common/include/exa_names.h"
#include "common/include/exa_assert.h"
#include "common/include/exa_constants.h"

#include "os/include/os_dir.h"
#include "os/include/os_error.h"
#include "os/include/os_file.h"
#include "os/include/os_thread.h"
#include "os/include/strlcpy.h"

#include "rdev/include/exa_rdev.h"

#include "libaio.h"

#include "rdev/src/rdev_perf.h"

#define EXA_RDEV_MODULE_PATH "/dev/" EXA_RDEV_MODULE_NAME

struct exa_rdev_handle
{
    io_context_t ctx;
    int fd;
#ifdef WITH_PERF
    rdev_perfs_t rdev_perfs;
#endif
};

static rdev_static_op_t init_op = RDEV_STATIC_OP_INVALID;

int exa_rdev_static_init(rdev_static_op_t op)
{
    EXA_ASSERT_VERBOSE(init_op == RDEV_STATIC_OP_INVALID, "static data already initialized");

    EXA_ASSERT_VERBOSE(op == RDEV_STATIC_CREATE || op == RDEV_STATIC_GET,
                       "invalid static init op: %d", op);

    init_op = op;

    return 0;
}

void exa_rdev_static_clean(rdev_static_op_t op)
{
    /* Initialization not performed, nothing to clean */
    if (init_op == RDEV_STATIC_OP_INVALID)
        return;

    EXA_ASSERT_VERBOSE(op == RDEV_STATIC_RELEASE || op == RDEV_STATIC_DELETE,
               "invalid static clean op: %d", op);

    if (op == RDEV_STATIC_DELETE)
    {
        EXA_ASSERT_VERBOSE(init_op == RDEV_STATIC_CREATE,
                           "deletion of static data by non-owner");
    }
    else /* RDEV_STATIC_RELEASE */
    {
        EXA_ASSERT_VERBOSE(init_op == RDEV_STATIC_GET,
                           "release of static data by owner");
    }

    init_op = RDEV_STATIC_OP_INVALID;
}

int exa_rdev_init(void)
{
    return 123;
}

exa_rdev_handle_t *exa_rdev_handle_alloc(const char *path)
{
    int err;
    exa_rdev_handle_t *handle;

    handle = os_malloc(sizeof(exa_rdev_handle_t));
    if (handle == NULL)
	return handle;

    handle->fd = open(path, O_RDWR);
    if (handle->fd < 0) {
	    perror("open error");
	    return NULL;
    }

    err = io_setup(128 /* FIXME get the kmodule value */, &handle->ctx);
    if (err < 0) {
	os_free(handle);
	return NULL;
    }

    rdev_perf_init(&handle->rdev_perfs, path);

    return handle;
}

void __exa_rdev_handle_free(exa_rdev_handle_t *handle)
{
    if (handle == NULL)
        return;

    /* Ignore error here: what could we do? */
    io_destroy(handle->ctx);

    os_free(handle);
}

int exa_rdev_flush(exa_rdev_handle_t *handle)
{
  if (handle == NULL)
    return -1;

  /* FIXME how to do that? */
  return 0;
}


int exa_rdev_make_request_new(rdev_op_t op, void **nbd_private,
			      unsigned long long sector, int sector_nb,
			      void *buffer, exa_rdev_handle_t *handle)
{
  struct iocb cb;
  struct iocb *cbs[1];
  int err;

  EXA_ASSERT(RDEV_OP_VALID(op));

  if (handle == NULL)
    return -1;

  memset(&cb, 0, sizeof(cb));
  cb.aio_fildes = handle->fd;
  cb.aio_lio_opcode = op == RDEV_OP_READ ? IO_CMD_PREAD : IO_CMD_PWRITE;

  /* command-specific options */
  cb.u.c.buf = buffer;
  cb.u.c.offset = sector * SECTOR_SIZE;
  cb.u.c.nbytes = sector_nb * SECTOR_SIZE;

  cbs[0] = &cb;

  err = io_submit(handle->ctx, 1, cbs);
  if (err != 1) {
      if (err < 0)
          perror("io_submit error");
      else
          fprintf(stderr, "could not sumbit IOs");
      return  -1;
  }

  return RDEV_REQUEST_NONE_ENDED;
}

int exa_rdev_wait_one_request(void **nbd_private,
                              exa_rdev_handle_t *handle)
{
    struct io_event events[1];
    int ret;

    if (handle == NULL)
	return -RDEV_ERR_NOT_OPEN;

    /* get the reply */
    ret = io_getevents(handle->ctx, 0, 1, events, NULL);
    printf("%d\n", ret);

    if (ret == 0)
	    return RDEV_REQUEST_ALL_ENDED;
    if (nbd_private == NULL)
        return -EINVAL;

    *nbd_private = NULL;

    return RDEV_REQUEST_END_OK;
}

int exa_rdev_get_last_error(const exa_rdev_handle_t *handle)
{
    return -RDEV_ERR_UNKNOWN;
}

int exa_rdev_activate(exa_rdev_handle_t *handle)
{
    return 0;
}

int exa_rdev_deactivate(exa_rdev_handle_t *handle, char *path)
{
    return 0;
}

