#include "internal.h"

/*
 *      The PCI Library -- Remote socket access method
 *
 *      Copyright (c) 2025 The PCI Utilities contributors
 *
 *      Can be freely distributed and used under the terms of the GNU GPL v2+.
 *
 *      SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <errno.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>

#ifdef PCI_HAVE_PM_REMOTE_SOCKET

#define REMOTE_DEFAULT_PORT 4001
#define REMOTE_DEFAULT_TIMEOUT_MS 5000

struct remote_ctx
{
  struct pci_access *acc;
  char *host;
  int port;
  int timeout_ms;
  int domain;
  int bus;
  int slot;
  int func;
  char slot_id[64];
  int host_auto;
};

static void
remote_config(struct pci_access *a)
{
  pci_define_param(a, "remote.slot", "", "Remote MCU slot specification [<host>[:<port>]@]<slot>");
  pci_define_param(a, "remote.timeout", "5000", "Remote MCU socket timeout in milliseconds");
}

static int
remote_detect(struct pci_access *a)
{
  char *spec = pci_get_param(a, "remote.slot");
  return spec && *spec;
}

static void
remote_free_ctx(struct remote_ctx *ctx)
{
  if (!ctx)
    return;
  if (ctx->host)
    pci_mfree(ctx->host);
  pci_mfree(ctx);
}

static void
remote_parse_slot(struct remote_ctx *ctx, struct pci_access *a, const char *spec)
{
  if (!spec || !*spec)
    a->error("Remote slot specification (--slot) is required");

  char *copy = pci_strdup(a, spec);
  char *slot_part = copy;
  char *host_part = NULL;
  char *at = strrchr(copy, '@');
  if (at)
    {
      *at = 0;
      slot_part = at + 1;
      host_part = copy;
    }

  if (!*slot_part)
    a->error("Remote slot specification missing device address");

  struct pci_filter filter;
  pci_filter_init(a, &filter);
  char *err = pci_filter_parse_slot(&filter, slot_part);
  if (err)
    a->error("Invalid remote slot specification: %s", err);
  if (filter.domain < 0 || filter.bus < 0 || filter.slot < 0 || filter.func < 0)
    a->error("Remote slot requires full domain:bus:slot.func specification");

  ctx->domain = filter.domain;
  ctx->bus = filter.bus;
  ctx->slot = filter.slot;
  ctx->func = filter.func;
  snprintf(ctx->slot_id, sizeof(ctx->slot_id), "%04x:%02x:%02x.%u",
           ctx->domain, ctx->bus, ctx->slot, ctx->func);

  if (host_part && *host_part)
    {
      char *host = host_part;
      char *port_str = NULL;

      if (host[0] == '[')
        {
          char *end = strchr(host, ']');
          if (!end)
            a->error("Invalid remote host specification: %s", host_part);
          *end = 0;
          host++;
          if (end[1] == ':')
            port_str = end + 2;
          else if (end[1])
            a->error("Invalid remote host specification: %s", host_part);
        }
      else
        {
          char *first_colon = strchr(host, ':');
          char *last_colon = strrchr(host, ':');
          if (first_colon && first_colon != last_colon)
            a->error("Invalid remote host specification: %s", host_part);
          if (last_colon)
            {
              *last_colon = 0;
              port_str = last_colon + 1;
            }
        }

      ctx->host = pci_strdup(a, *host ? host : "");
      if (port_str && *port_str)
        {
          char *end;
          long port = strtol(port_str, &end, 10);
          if (*end || port <= 0 || port > 65535)
            a->error("Invalid remote port value: %s", port_str);
          ctx->port = port;
        }
      else
        ctx->port = REMOTE_DEFAULT_PORT;
      ctx->host_auto = 0;
    }
  else
    {
      ctx->host = NULL;
      ctx->port = REMOTE_DEFAULT_PORT;
      ctx->host_auto = 1;
    }

  pci_mfree(copy);
}

static void
remote_select_default_host(struct remote_ctx *ctx)
{
  struct pci_access *a = ctx->acc;
  struct ifaddrs *ifaddr;

  if (getifaddrs(&ifaddr) < 0)
    a->error("Unable to enumerate network interfaces: %s", strerror(errno));

  struct ifaddrs *ifa;
  unsigned int bus = (unsigned int) (ctx->bus & 0xff);
  unsigned int slot = (unsigned int) (ctx->slot & 0xff);
  unsigned int expected_local_octet = slot + 0x10;

  for (ifa = ifaddr; ifa; ifa = ifa->ifa_next)
    {
      if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET)
        continue;

      struct sockaddr_in *sa = (struct sockaddr_in *) ifa->ifa_addr;
      uint32_t ip = ntohl(sa->sin_addr.s_addr);

      unsigned int o0 = (ip >> 24) & 0xff;
      unsigned int o1 = (ip >> 16) & 0xff;
      unsigned int o2 = (ip >> 8) & 0xff;
      unsigned int o3 = ip & 0xff;

      if (o0 != 192 || o1 != 168)
        continue;
      if (o2 != bus)
        continue;
      if (o3 != expected_local_octet)
        continue;

      char buf[INET_ADDRSTRLEN];
      snprintf(buf, sizeof(buf), "192.168.%u.%u", o2, slot);
      ctx->host = pci_strdup(a, buf);
      freeifaddrs(ifaddr);
      return;
    }

  freeifaddrs(ifaddr);
  a->error("Unable to infer remote MCU address for %s", ctx->slot_id);
}

static void
remote_parse_timeout(struct remote_ctx *ctx, struct pci_access *a)
{
  char *val = pci_get_param(a, "remote.timeout");
  if (val && *val)
    {
      char *end;
      long timeout = strtol(val, &end, 10);
      if (*end || timeout < 0 || timeout > 600000)
        a->error("Invalid remote timeout value: %s", val);
      ctx->timeout_ms = timeout;
    }
  else
    ctx->timeout_ms = REMOTE_DEFAULT_TIMEOUT_MS;
}

static void
remote_init(struct pci_access *a)
{
  struct remote_ctx *ctx = pci_malloc(a, sizeof(*ctx));
  memset(ctx, 0, sizeof(*ctx));
  ctx->acc = a;

  const char *spec = pci_get_param(a, "remote.slot");
  remote_parse_slot(ctx, a, spec);
  remote_parse_timeout(ctx, a);

  if (ctx->host_auto)
    remote_select_default_host(ctx);
  else if (!ctx->host || !*ctx->host)
    ctx->host = pci_strdup(a, "127.0.0.1");

  a->backend_data = ctx;
}

static void
remote_cleanup(struct pci_access *a)
{
  remote_free_ctx(a->backend_data);
  a->backend_data = NULL;
}

static void
remote_validate_device(struct remote_ctx *ctx, struct pci_dev *d)
{
  if (d->domain != ctx->domain || d->bus != ctx->bus ||
      d->dev != ctx->slot || d->func != ctx->func)
    ctx->acc->error("Remote socket backend only provides %s", ctx->slot_id);
}

static int
remote_open_socket(struct remote_ctx *ctx)
{
  struct addrinfo hints;
  memset(&hints, 0, sizeof(hints));
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_family = AF_UNSPEC;

  char port_buf[16];
  snprintf(port_buf, sizeof(port_buf), "%d", ctx->port);

  struct addrinfo *ai = NULL;
  int err = getaddrinfo(ctx->host, port_buf, &hints, &ai);
  if (err)
    ctx->acc->error("Unable to resolve remote host %s: %s", ctx->host, gai_strerror(err));

  int fd = -1;
  for (struct addrinfo *p = ai; p; p = p->ai_next)
    {
      fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
      if (fd < 0)
        continue;

      struct timeval tv;
      tv.tv_sec = ctx->timeout_ms / 1000;
      tv.tv_usec = (ctx->timeout_ms % 1000) * 1000;
      if (ctx->timeout_ms)
        {
          setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
          setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        }

      if (!connect(fd, p->ai_addr, p->ai_addrlen))
        break;

      close(fd);
      fd = -1;
    }

  freeaddrinfo(ai);

  if (fd < 0)
    ctx->acc->error("Unable to connect to remote MCU at %s:%d", ctx->host, ctx->port);

  return fd;
}

static int
remote_send_all(int fd, const void *buf, size_t len)
{
  const char *p = buf;
  while (len)
    {
      ssize_t w = send(fd, p, len, 0);
      if (w < 0)
        {
          if (errno == EINTR)
            continue;
          return -1;
        }
      p += w;
      len -= w;
    }
  return 0;
}

static int
remote_recv_all(int fd, void *buf, size_t len)
{
  char *p = buf;
  while (len)
    {
      ssize_t r = recv(fd, p, len, 0);
      if (r < 0)
        {
          if (errno == EINTR)
            continue;
          return -1;
        }
      if (!r)
        return -1;
      p += r;
      len -= r;
    }
  return 0;
}

static int
remote_read_word(struct remote_ctx *ctx, unsigned int regaddr, u16 *value)
{
  int fd = remote_open_socket(ctx);

  unsigned char req[8];
  req[0] = 0x02;
  req[1] = 0x02;
  req[2] = 0x0a;
  req[3] = (regaddr >> 16) & 0xff;
  req[4] = regaddr & 0xff;
  req[5] = (regaddr >> 8) & 0xff;
  req[6] = 0x02;
  req[7] = 0x00;

  if (remote_send_all(fd, req, sizeof(req)) < 0)
    {
      close(fd);
      ctx->acc->error("Failed to send read request to remote MCU");
    }

  unsigned char resp[3];
  if (remote_recv_all(fd, resp, sizeof(resp)) < 0)
    {
      close(fd);
      ctx->acc->error("Failed to receive read response from remote MCU");
    }
  close(fd);

  if (resp[0] != 0x00)
    ctx->acc->error("Remote MCU reported read failure (status 0x%02x)", resp[0]);

  *value = resp[1] | ((u16) resp[2] << 8);
  return 1;
}

static int
remote_write_word(struct remote_ctx *ctx, unsigned int regaddr, u16 value)
{
  int fd = remote_open_socket(ctx);

  unsigned char req[10];
  req[0] = 0x04;
  req[1] = 0x02;
  req[2] = 0x0a;
  req[3] = (regaddr >> 16) & 0xff;
  req[4] = regaddr & 0xff;
  req[5] = (regaddr >> 8) & 0xff;
  req[6] = 0x02;
  req[7] = 0x00;
  req[8] = value & 0xff;
  req[9] = (value >> 8) & 0xff;

  if (remote_send_all(fd, req, sizeof(req)) < 0)
    {
      close(fd);
      ctx->acc->error("Failed to send write request to remote MCU");
    }

  unsigned char resp[3];
  if (remote_recv_all(fd, resp, sizeof(resp)) < 0)
    {
      close(fd);
      ctx->acc->error("Failed to receive write response from remote MCU");
    }
  close(fd);

  if (resp[0] != 0x00)
    ctx->acc->error("Remote MCU reported write failure (status 0x%02x)", resp[0]);
  return 1;
}

static unsigned int
remote_regaddr(const struct remote_ctx *ctx, unsigned int pos)
{
  unsigned int bus = (unsigned int) (ctx->bus & 0xff);
  unsigned int slot = (unsigned int) (ctx->slot & 0xff);
  unsigned int func = (unsigned int) (ctx->func & 0x07);
  unsigned int offset = pos & ~1U;

  return (bus << 16) | (slot << 11) | (func << 8) | (offset & 0xff);
}

static int
remote_read(struct pci_dev *d, int pos, byte *buf, int len)
{
  struct remote_ctx *ctx = d->access->backend_data;
  remote_validate_device(ctx, d);
  int processed = 0;

  while (processed < len)
    {
      int cur_pos = pos + processed;
      unsigned int addr = remote_regaddr(ctx, cur_pos);
      u16 value;

      remote_read_word(ctx, addr, &value);

      if (cur_pos & 1)
        {
          buf[processed++] = value >> 8;
        }
      else
        {
          buf[processed++] = value & 0xff;
          if (processed < len)
            buf[processed++] = value >> 8;
        }
    }

  return 1;
}

static int
remote_write(struct pci_dev *d, int pos, byte *buf, int len)
{
  struct remote_ctx *ctx = d->access->backend_data;
  remote_validate_device(ctx, d);
  int processed = 0;

  while (processed < len)
    {
      int cur_pos = pos + processed;
      unsigned int addr = remote_regaddr(ctx, cur_pos);
      u16 value;

      if ((cur_pos & 1) || (len - processed) == 1)
        {
          remote_read_word(ctx, addr, &value);
          if (cur_pos & 1)
            {
              value = (value & 0x00ff) | ((u16)buf[processed] << 8);
            }
          else
            {
              value = (value & 0xff00) | buf[processed];
            }
          processed++;
        }
      else
        {
          value = buf[processed] | ((u16)buf[processed + 1] << 8);
          processed += 2;
        }

      remote_write_word(ctx, addr, value);
    }

  return 1;
}

static void
remote_scan(struct pci_access *a)
{
  struct remote_ctx *ctx = a->backend_data;
  struct pci_dev *d = pci_alloc_dev(a);

  d->domain = ctx->domain;
  d->bus = ctx->bus;
  d->dev = ctx->slot;
  d->func = ctx->func;

  pci_link_dev(a, d);
}

struct pci_methods pm_remote_socket = {
  .name = "remote-socket",
  .help = "Remote MCU access via TCP socket",
  .config = remote_config,
  .detect = remote_detect,
  .init = remote_init,
  .cleanup = remote_cleanup,
  .scan = remote_scan,
  .fill_info = pci_generic_fill_info,
  .read = remote_read,
  .write = remote_write,
  .read_vpd = NULL,
  .init_dev = NULL,
  .cleanup_dev = NULL,
};

#endif
