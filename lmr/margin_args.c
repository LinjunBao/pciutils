/*
 *	The PCI Utilities -- Parse pcilmr utility arguments
 *
 *	Copyright (c) 2024 KNS Group LLC (YADRO)
 *
 *	Can be freely distributed and used under the terms of the GNU GPL v2+.
 *
 *	SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lmr.h"

const char *usage
  = "! Utility requires preliminary preparation of the system. Refer to the pcilmr man page !\n\n"
    "Brief usage (see man for all options):\n"
    "pcilmr [--margin] [<common options>] <link port> [<link options>] [<link port> [<link "
    "options>] ...]\n"
    "pcilmr --full [<common options>]\n"
    "pcilmr --scan\n\n"
    "You can specify Downstream or Upstream Port of the Link.\nPort Specifier:\n"
    "<device/component>:\t[<domain>:]<bus>:<dev>.<func>\n\n"
    "Modes:\n"
    "--margin\t\tMargin selected Links\n"
    "--full\t\t\tMargin all ready for testing Links in the system (one by one)\n"
    "--scan\t\t\tScan for Links available for margining\n\n"
    "Margining options (see man for all options):\n\n"
    "Common (for all specified links) options:\n"
    "-c\t\t\tPrint Device Lane Margining Capabilities only. Do not run margining.\n\n"
    "Link specific options:\n"
    "-r <recvn>[,<recvn>...]\tSpecify Receivers to select margining targets.\n"
    "\t\t\tDefault: all available Receivers (including Retimers).\n"
    "-t <steps>\t\tSpecify maximum number of steps for Time Margining.\n"
    "-v <steps>\t\tSpecify maximum number of steps for Voltage Margining.\n";

bool
margin_parse_dut_identifier(const char *spec, struct margin_dut_identifier *out)
{
  if (!spec || !*spec || !out)
    return false;

  const char *slot_part = strrchr(spec, '@');
  size_t host_len = 0;
  if (slot_part)
    {
      host_len = slot_part - spec;
      slot_part++;
    }
  else
    slot_part = spec;

  while (*slot_part && isspace((unsigned char)*slot_part))
    slot_part++;

  if (!*slot_part)
    return false;

  const char *p = slot_part;
  const char *prefix_end = p;

  if (tolower((unsigned char)p[0]) == 's'
      && tolower((unsigned char)p[1]) == 'l'
      && tolower((unsigned char)p[2]) == 'o'
      && tolower((unsigned char)p[3]) == 't')
    prefix_end = p + 4;
  else if (tolower((unsigned char)p[0]) == 'd'
           && tolower((unsigned char)p[1]) == 'u'
           && tolower((unsigned char)p[2]) == 't')
    prefix_end = p + 3;
  else
    return false;

  p = prefix_end;
  while (*p && !isdigit((unsigned char)*p))
    {
      if (isalpha((unsigned char)*p))
        return false;
      p++;
    }

  if (!isdigit((unsigned char)*p))
    return false;

  const char *digits_start = p;
  unsigned int slot = 0;
  while (isdigit((unsigned char)*p))
    {
      slot = slot * 10 + (*p - '0');
      if (slot > 255)
        return false;
      p++;
    }

  const char *digits_end = p;

  while (*p)
    {
      if (isspace((unsigned char)*p) || *p == '_' || *p == '-')
        {
          p++;
          continue;
        }
      return false;
    }

  if (!slot)
    return false;

  size_t pos = 0;
  if (host_len)
    {
      if (host_len >= sizeof(out->remote_spec))
        return false;
      memcpy(out->remote_spec, spec, host_len);
      pos = host_len;
      if (pos + 1 >= sizeof(out->remote_spec))
        return false;
      out->remote_spec[pos++] = '@';
    }

  size_t digits_len = digits_end - digits_start;
  if (!digits_len || pos + digits_len >= sizeof(out->remote_spec))
    return false;

  memcpy(out->remote_spec + pos, digits_start, digits_len);
  pos += digits_len;
  out->remote_spec[pos] = '\0';
  out->slot = slot;
  return true;
}

static struct pci_dev *
dev_for_filter(struct pci_access *pacc, char *filter, bool *skip_role_check)
{
  *skip_role_check = false;

  char slot_address[32];
  char *filter_value = filter;

  struct margin_dut_identifier dut;
  if (margin_parse_dut_identifier(filter, &dut))
    {
      if (snprintf(slot_address, sizeof(slot_address), "%04x:%02x:%02x.%u", 0, 0, dut.slot, 0)
          >= (int)sizeof(slot_address))
        die("Invalid remote slot identifier: %s\n", filter);

      filter_value = slot_address;
      *skip_role_check = true;
    }

  struct pci_filter pci_filter;
  pci_filter_init(pacc, &pci_filter);
  if (pci_filter_parse_slot(&pci_filter, filter_value))
    die("Invalid device ID: %s\n", filter);

  if (pci_filter.bus == -1 || pci_filter.slot == -1 || pci_filter.func == -1)
    die("Invalid device ID: %s\n", filter);

  if (pci_filter.domain == -1)
    pci_filter.domain = 0;

  for (struct pci_dev *p = pacc->devices; p; p = p->next)
    {
      if (pci_filter_match(&pci_filter, p))
        return p;
    }

  die("No such PCI device: %s or you don't have enough privileges.\n", filter);
}

static u8
parse_csv_arg(char *arg, u8 *vals)
{
  u8 cnt = 0;
  char *token = strtok(arg, ",");
  while (token)
    {
      vals[cnt] = atoi(token);
      cnt++;
      token = strtok(NULL, ",");
    }
  return cnt;
}

static u8
find_ready_links(struct pci_access *pacc, struct margin_link *links, bool cnt_only)
{
  u8 cnt = 0;
  for (struct pci_dev *p = pacc->devices; p; p = p->next)
    {
      if (pci_find_cap(p, PCI_EXT_CAP_ID_LMR, PCI_CAP_EXTENDED) && margin_port_is_down(p))
        {
          struct pci_dev *down = NULL;
          struct pci_dev *up = NULL;
          margin_find_pair(pacc, p, &down, &up);

          if (down && margin_verify_link(down, up, false)
              && (margin_check_ready_bit(down) || margin_check_ready_bit(up)))
            {
              if (!cnt_only)
                margin_fill_link(down, up, &(links[cnt]), false);
              cnt++;
            }
        }
    }
  return cnt;
}

static void
init_link_args(struct margin_link_args *link_args, struct margin_com_args *com_args)
{
  memset(link_args, 0, sizeof(*link_args));
  link_args->common = com_args;
  link_args->parallel_lanes = 1;
}

static void
parse_dev_args(int argc, char **argv, struct margin_link_args *args, u8 link_speed)
{
  if (argc == optind)
    return;
  int c;
  while ((c = getopt(argc, argv, "+r:l:p:t:v:VTg:")) != -1)
    {
      switch (c)
        {
          case 't':
            args->steps_t = atoi(optarg);
            break;
          case 'T':
            args->steps_t = 63;
            break;
          case 'v':
            args->steps_v = atoi(optarg);
            break;
          case 'V':
            args->steps_v = 127;
            break;
          case 'p':
            args->parallel_lanes = atoi(optarg);
            break;
          case 'l':
            args->lanes_n = parse_csv_arg(optarg, args->lanes);
            break;
          case 'r':
            args->recvs_n = parse_csv_arg(optarg, args->recvs);
            break;
            case 'g': {
              char recv[2] = { 0 };
              char dir[2] = { 0 };
              char unit[4] = { 0 };
              float criteria = 0.0;
              char eye[2] = { 0 };
              int cons[3] = { 0 };

              int ret = sscanf(optarg, "%1[1-6]%1[tv]=%f%n%3[%,ps]%n%1[f]%n", recv, dir, &criteria,
                               &cons[0], unit, &cons[1], eye, &cons[2]);
              if (ret < 3)
                {
                  ret = sscanf(optarg, "%1[1-6]%1[tv]=%1[f]%n,%f%n%2[ps%]%n", recv, dir, eye,
                               &cons[0], &criteria, &cons[1], unit, &cons[2]);
                  if (ret < 3)
                    die("Invalid arguments\n\n%s", usage);
                }

              int consumed = 0;
              for (int i = 0; i < 3; i++)
                if (cons[i] > consumed)
                  consumed = cons[i];
              if ((size_t)consumed != strlen(optarg))
                die("Invalid arguments\n\n%s", usage);
              if (criteria < 0)
                die("Invalid arguments\n\n%s", usage);
              if (strstr(unit, ",") && eye[0] == 0)
                die("Invalid arguments\n\n%s", usage);

              u8 recv_n = recv[0] - '0' - 1;
              if (dir[0] == 'v')
                {
                  if (unit[0] != ',' && unit[0] != 0)
                    die("Invalid arguments\n\n%s", usage);
                  args->recv_args[recv_n].v.valid = true;
                  args->recv_args[recv_n].v.criteria = criteria;
                  if (eye[0] != 0)
                    args->recv_args[recv_n].v.one_side_is_whole = true;
                }
              else
                {
                  if (unit[0] == '%')
                    criteria = criteria / 100.0 * margin_ui[link_speed];
                  else if (unit[0] != 0 && (unit[0] != 'p' || unit[1] != 's'))
                    die("Invalid arguments\n\n%s", usage);
                  else if (unit[0] == 0 && criteria != 0)
                    die("Invalid arguments\n\n%s", usage);
                  args->recv_args[recv_n].t.valid = true;
                  args->recv_args[recv_n].t.criteria = criteria;
                  if (eye[0] != 0)
                    args->recv_args[recv_n].t.one_side_is_whole = true;
                }
              break;
            }
          case '?':
            die("Invalid arguments\n\n%s", usage);
            break;
          default:
            return;
        }
    }
}

struct margin_link *
margin_parse_util_args(struct pci_access *pacc, int argc, char **argv, enum margin_mode mode,
                       u8 *links_n)
{
  struct margin_com_args *com_args = xmalloc(sizeof(*com_args));
  com_args->error_limit = 5;
  com_args->run_margin = true;
  com_args->verbosity = 1;
  com_args->steps_utility = 0;
  com_args->dir_for_csv = NULL;
  com_args->save_csv = false;
  com_args->dwell_time = 10;

  int c;
  while ((c = getopt(argc, argv, "+e:co:d:")) != -1)
    {
      switch (c)
        {
          case 'c':
            com_args->run_margin = false;
            break;
          case 'e':
            com_args->error_limit = atoi(optarg);
            break;
          case 'o':
            com_args->dir_for_csv = optarg;
            com_args->save_csv = true;
            break;
          case 'd':
            com_args->dwell_time = atoi(optarg);
            break;
          default:
            die("Invalid arguments\n\n%s", usage);
        }
    }

  bool status = true;
  if (mode == FULL && optind != argc)
    status = false;
  if (mode == MARGIN && optind == argc)
    status = false;
  if (!status && argc > 1)
    die("Invalid arguments\n\n%s", usage);
  if (!status)
    {
      printf("%s", usage);
      exit(0);
    }

  u8 ports_n = 0;
  struct margin_link *links = NULL;
  char err[128];

  if (mode == FULL)
    {
      ports_n = find_ready_links(pacc, NULL, true);
      if (ports_n == 0)
        die("Links not found or you don't have enough privileges.\n");
      else
        {
          links = xmalloc(ports_n * sizeof(*links));
          find_ready_links(pacc, links, false);
          for (int i = 0; i < ports_n; i++)
            init_link_args(&(links[i].args), com_args);
        }
    }
  else if (mode == MARGIN)
    {
      while (optind != argc)
        {
          bool skip_role_check;
          struct pci_dev *dev = dev_for_filter(pacc, argv[optind], &skip_role_check);
          optind++;
          links = xrealloc(links, (ports_n + 1) * sizeof(*links));
          struct pci_dev *down;
          struct pci_dev *up;
          if (!margin_find_pair(pacc, dev, &down, &up))
            die("Cannot find pair for the specified device: %s\n", argv[optind - 1]);
          struct pci_cap *cap = pci_find_cap(down, PCI_CAP_ID_EXP, PCI_CAP_NORMAL);
          if (!cap)
            die("Looks like you don't have enough privileges to access "
                "Device Configuration Space.\nTry to run utility as root.\n");
          if (!margin_fill_link(down, up, &(links[ports_n]), skip_role_check))
            {
              margin_gen_bdfs(down, up, err, sizeof(err));
              die("Link %s is not ready for margining.\n"
                  "Link data rate must be 16 GT/s or 32 GT/s.\n"
                  "Downstream Component must be at D0 PM state.\n",
                  err);
            }
          init_link_args(&(links[ports_n].args), com_args);
          parse_dev_args(argc, argv, &(links[ports_n].args),
                         links[ports_n].down_port.link_speed - 4);
          ports_n++;
        }
    }
  else
    die("Bug in the args parsing!\n");

  *links_n = ports_n;
  return links;
}
