#pragma once

int get_fd(void);
int put_fd(int fd);
void* find_fd(int fd);
int set_fd(int fd, void* data);