#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/fcntl.h>
#include <sys/stat.h>

#define BUF_SIZE 256

static char *buf;
static int locked;
static int idx;
static int value;
static int source;
static int dest;
static int length;
static char* big_buffer;
static int admin;

static int parse_int(const char* src, int* num_consumed, char* convert_buf)
{
  int consumed = 0;
  char* dest = convert_buf;
  while (*src != ':')
  {
    /* Warning: this routine requires a convert_buf of at least 11 charcters:
     * 4294967295 plus trailing NUL.
     */
    *dest = *src;
    consumed++;
    dest++;
    src++;
  }
  *dest = '\0';
  *num_consumed = consumed;
  return atoi(convert_buf);
}

int
main(int argc, const char* argv[])
{
  char convert_buf[11];
  int consumed;
  (void) argc;
  (void) argv;
  /* Security: start locked by default. */
  locked = 1;
  admin = 0;

  /* Set up the secure and temporary storage areas. */
  chdir(getenv("HOME"));
  mkdir("buggy_server", 0777);
  mkdir("buggy_server/secure", 0777);
  system("/bin/echo -n -e '\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff' > buggy_server/secure/hash");
  system("/bin/echo -n -e '\xbc\x25\x0e\x0d\x83\xc3\x7b\x09\x53\xad\xa1\x4e\x7b\xbc\x1d\xfd' > buggy_server/secure/admin_hash");
  system("/bin/echo -n -e '\x7f\xc7\x32\xff\x0f\x10\x41\x54\xdd\x53\xe8\xd4\x52\x3b\xb1\x92' > buggy_server/secure/superadmin_hash");
  mkdir("buggy_server/tmp", 0777);
  chdir("buggy_server/tmp");

  while (1)
  {
    buf = malloc(sizeof(char) * BUF_SIZE);
    ssize_t num_read = read(0, buf, sizeof buf);

    if (num_read <= 0)
    {
      /* End-Of-File or error. */
      exit(0);
    }
    /* Make sure the incoming buffer is NUL terminated, in case it contains
     * a string.
     */
    if (buf[sizeof(buf) - 1] != '\0')
    {
      buf[sizeof(buf)] = '\0';
    }
    switch (buf[0])
    {
    case 'A':
      /* Zero buffer. */
      memset(buf, 0, sizeof buf);
      break;
    case 'B':
      /* Get buffer character. */
      idx = (char) parse_int(buf + 1, &consumed, convert_buf);
      /* Safe to use index verbatim because we truncated in to an 8-bit value,
       * and the buffer is 8-bits wide (256 chars).
       */
      write(1, &buf[idx], 1);
      break;
    case 'C':
      /* Set buffer character. */
      idx = (char) parse_int(buf + 1, &consumed, convert_buf);
      value = (char) parse_int(buf + consumed + 2, &consumed, convert_buf);
      buf[idx] = value;
      break;
    case 'D':
      /* Allocate big_buffer. */
      length = parse_int(buf + 1, &consumed, convert_buf);
      /* Give enough room to store the length. */
      length += 4;
      /* We store the length of the buffer at the start of the buffer itself so
       * that we can retrieve it to check against it.
       */
      big_buffer = malloc(length);
      big_buffer[0] = length & 0xff;
      big_buffer[1] = (length >> 8) & 0xff;
      big_buffer[2] = (length >> 16) & 0xff;
      big_buffer[3] = (length >> 24) & 0xff;
      break;
    case 'E':
      /* Discard big_buffer. */
      if (big_buffer)
      {
        free(big_buffer);
      }
      break;
    case 'F':
      /* Copy in to big_buffer. */
      idx = 1;
      source = parse_int(buf + idx, &consumed, convert_buf);
      idx += consumed + 1;
      dest = parse_int(buf + idx, &consumed, convert_buf);
      idx += consumed + 1;
      length = parse_int(buf + idx, &consumed, convert_buf);

      /* Make sure the request is sane, and does not overflow. */
      if (source + length > 256 ||
          dest >= *(int*)big_buffer)
      {
        /* Buffer overflow! */
        return -1;
      }
      memcpy(big_buffer + dest, buf + source, length);
      break;
    case 'G':
      /* Echo! */
      write(1, buf, strlen(buf));
      break;
    case 'H':
      /* SUPER ADMIN ONLY: execute. */
      if (!locked)
      {
        system(buf);
      }
      break;
    case 'I':
      /* Notify that proposed password is in big_buffer. */
      {
        char cmd_buffer[4096];
        int written = sprintf(cmd_buffer, "/bin/echo -n '");
        written += sprintf(cmd_buffer + written, big_buffer);
        sprintf(cmd_buffer + written, "' | md5sum | xxd -r -p > ../secure/hash");
        system(cmd_buffer);
      }
      break;
    case 'J':
      /* Check SUPER ADMIN password! */
      {
        char hash1[17];
        char hash2[17];
        int fd;
        memset(hash1, 0, 17);
        memset(hash2, 0, 17);
        fd = open("../secure/superadmin_hash", O_RDONLY);
        read(fd, hash1, 16);
        fd = open("../secure/hash", O_RDONLY);
        read(fd, hash2, 16);
        if (!strncmp(hash1, hash2, strlen(hash2)))
        {
          write(1, "SUPER ADMIN OK", 16);
          locked = 0;
        }
        else
        {
          write(1, "SUPER ADMIN BAD", 16);
        }
      }
      break;
    case 'K':
      /* Check admin password. */
      {
        char hash1[16];
        char hash2[16];
        int fd;
        int i;
        int failed = 0;
        memset(hash1, 0, 16);
        memset(hash2, 0, 16);
        fd = open("../secure/admin_hash", O_RDONLY);
        read(fd, hash1, 16);
        fd = open("../secure/hash", O_RDONLY);
        read(fd, hash2, 16);
        for (i = 0; i < 16; ++i)
        {
          if (hash1[i] != hash2[i])
          {
            failed = 1;
          }
        }
        if (!failed)
        {
          admin = 1;
          write(1, "YES", 3);
        }
        else
        {
          write(1, "NO", 2);
        }
      }
      break;
    case 'L':
      /* Write file to tmp. Requires admin or superadmin. */
      if (!admin && locked)
      {
	printf("not pass");
        break;
      }
      /* 16 bytes are written to a single character filename. */
      buf[2] = '\0';
      {
	printf("pass");
        int fd = open(buf + 1, O_CREAT | O_EXCL | O_WRONLY, 0777);
        write(fd, &buf[3], 16);
      }
      break;
    case 'M':
      /* Delete file from tmp. Requires admin or superadmin. */
      if (admin || !locked)
      {
        /* Avoid directory traversal. This check is stricter than neccessary in
         * that it will reject the path a..b even though that is a regular file
         * and not a directory traversal. We can live with it.
         */
        if (strstr(buf + 1, ".."))
        {
          break;
        }
        /* Convert \n to NUL otherwise it's a hassle to use interactively. */
        if (strchr(buf + 1, '\n'))
        {
          *strchr(buf + 1, '\n') = '\0';
        }
        unlink(buf + 1);
      }
      break;
#ifndef NDEBUG
    case 'N':
      /* Debug builds only: sleep. */
      {
        unsigned int sleep_val = parse_int(buf + 1, &consumed, convert_buf);
        unsigned int count = 0;
        unsigned int exp = 1;
        /* Apply log scale. */
        while (exp < sleep_val)
        {
          exp <<= 1;
          count++;
        }
        sleep(count);
      }
      break;
#endif
    case 'O':
      /* Copy out of big_buffer. */
      idx = 1;
      source = parse_int(buf + idx, &consumed, convert_buf);
      idx += consumed + 1;
      dest = parse_int(buf + idx, &consumed, convert_buf);
      idx += consumed + 1;
      length = parse_int(buf + idx, &consumed, convert_buf);

      /* Make sure the request is sane, and does not overflow. */
      if (length > 256 || length > *(int*)big_buffer ||
          source >= 256 || dest >= *(int*)big_buffer)
      {
        /* Buffer overflow! */
        break;
      }
      memcpy(buf + dest, big_buffer + source, length);
      break;
    case 'P':
      /* Fill big buffer */
      length = *(int*)big_buffer;
      memset(big_buffer, buf[1], length);
      big_buffer[length - 1] = '\0';
    }
  }
}
