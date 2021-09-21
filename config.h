#ifndef CONFIG_H
#define CONFIG_H

#include "hashmap.h"

#define SUPPORTED_VERSION       1

int configParse(char *path, struct hashmap *users);

#endif // CONFIG_H
