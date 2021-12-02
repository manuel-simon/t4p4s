// SPDX-License-Identifier: Apache-2.0
// Copyright 2016 Eotvos Lorand University, Budapest, Hungary

#include "controller.h"
#include "messages.h"
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

#define MAX_ENTRIES 2097152

#define TYPE uint32_t
#define SIZE 1

controller c;

extern void notify_controller_initialized();

void fill_table(TYPE count[], TYPE key)
{
    char buffer[2048];
    struct p4_header* h;
    struct p4_add_table_entry* te;
    struct p4_action* a;
    struct p4_action_parameter* ap[SIZE];
    // struct p4_field_match_header* fmh;
    struct p4_field_match_exact* exact;

    h = create_p4_header(buffer, 0, 2048);
    te = create_p4_add_table_entry(buffer,0,2048);
    strcpy(te->table_name, "table0_0");

    exact = add_p4_field_match_exact(te, 2048);
    strcpy(exact->header.name, "custom.payload1");
    memcpy(exact->bitmap, &key, sizeof(TYPE));
    exact->length = sizeof(TYPE)*8+0;



    a = add_p4_action(h, 2048);
    strcpy(a->description.name, "forward");

    for (uint32_t i = 0; i < SIZE; i++) {
        ap[i] = add_p4_action_parameter(h, a, 2048);
        char name[11];
        sprintf(name, "count%05d", i);
        strcpy(ap[i]->name, name);
        memcpy(ap[i]->bitmap, &count[i], (sizeof(TYPE)));
        ap[i]->length = (sizeof(TYPE)) * 8;
    }

    netconv_p4_header(h);
    netconv_p4_add_table_entry(te);
    netconv_p4_field_match_exact(exact);
    netconv_p4_action(a);
    
    for (uint32_t i = 0; i < SIZE; i++) {
	    netconv_p4_action_parameter(ap[i]);
    }

    send_p4_msg(c, buffer, 2048);
}

void change_entry(TYPE count[], TYPE key) {
    char buffer[2048];
    struct p4_header* h;
    struct p4_change_table_entry* te;
    struct p4_action* a;
    struct p4_action_parameter* ap[SIZE];
    struct p4_field_match_exact* exact;

    h = create_p4_header(buffer, 0, 2048);
    te = create_p4_change_table_entry(buffer,0,2048);
    strcpy(te->table_name, "table0_0");

    exact = add_p4_field_match_exact(te, 2048);
    strcpy(exact->header.name, "custom.payload1");
    memcpy(exact->bitmap, &key, sizeof(TYPE));
    exact->length = sizeof(TYPE)*8+0;

    a = add_p4_action(h, 2048);
    strcpy(a->description.name, "forward");

    for (uint32_t i = 0; i < SIZE; i++) {
        ap[i] = add_p4_action_parameter(h, a, 2048);
        char name[11];
        sprintf(name, "count%05d", i);
        strcpy(ap[i]->name, name);
        memcpy(ap[i]->bitmap, &count[i], (sizeof(TYPE)));
        ap[i]->length = (sizeof(TYPE)) * 8;
    }


    netconv_p4_header(h);
    netconv_p4_change_table_entry(te);
    netconv_p4_field_match_exact(exact);
    netconv_p4_action(a);

    for (uint32_t i = 0; i < SIZE; i++) {
        netconv_p4_action_parameter(ap[i]);
    }

    send_p4_msg(c, buffer, 2048);
}

void change_table_entry(void* b) {
    TYPE key;
    TYPE counter[1];
    uint16_t offset=0;
    offset = sizeof(struct p4_digest);
    struct p4_digest_field* df = netconv_p4_digest_field(unpack_p4_digest_field(b, offset));
    memcpy(&key, df->value, sizeof(TYPE));
    offset += sizeof(struct p4_digest_field);
    df = netconv_p4_digest_field(unpack_p4_digest_field(b, offset));
    memcpy(&counter[0], df->value, sizeof(TYPE));
    change_entry(counter, key);
}

void dhf(void* b) {
    struct p4_header* h = netconv_p4_header(unpack_p4_header(b, 0));
    if (h->type != P4T_DIGEST) {
        printf("Method is not implemented\n");
        return;
    }

    struct p4_digest* d = unpack_p4_digest(b,0);
    if (strcmp(d->field_list_name, "change_table_entry")==0) {
        change_table_entry(b);
    } else {
        printf("Unknown digest received: X%sX\n", d->field_list_name);
    }
}

void set_default_action_smac()
{
    char buffer[2048];
    struct p4_header* h;
    struct p4_set_default_action* sda;
    struct p4_action* a;

    printf("Generate set_default_action message for table smac\n");

    h = create_p4_header(buffer, 0, sizeof(buffer));

    sda = create_p4_set_default_action(buffer,0,sizeof(buffer));
    strcpy(sda->table_name, "table0_0");

    a = &(sda->action);
    strcpy(a->description.name, "_drop");

    netconv_p4_header(h);
    netconv_p4_set_default_action(sda);
    netconv_p4_action(a);

    send_p4_msg(c, buffer, sizeof(buffer));
}


TYPE entry[MAX_ENTRIES];
TYPE countmap[MAX_ENTRIES][SIZE];
int entry_count = -1;

int read_entries_from_file(char *filename) {
    FILE *f;
    char line[200];
    TYPE key;
    int i;
    char* ptr;

    f = fopen(filename, "r");
    if (f == NULL) return -1;

    while (fgets(line, sizeof(line), f)) {
	    line[strlen(line)-1] = '\0';
	    if (entry_count==MAX_ENTRIES-1)
	    {
		printf("Too many entries...\n");
		break;
	    }

	    ptr = strtok(line, " ");
	    TYPE c;
	    i = 0;
	    if (ptr != NULL) {
		sscanf(ptr, "%d", &c);
		ptr = strtok(NULL, " ");
		entry[entry_count] = (TYPE) c;
	    }
	    while(ptr != NULL) {
		sscanf(ptr, "%d", &c);
		ptr = strtok(NULL, " ");
		if (i >= SIZE) {
		    printf("Too many entries...\n");
		    break;
		}
		countmap[entry_count][i++] = (TYPE) c;
	    }

	    entry_count++;
    }

    fclose(f);
    return 0;
}

void init() {
    int i;
    printf("Set default actions.\n");
    set_default_action_smac();

    for (i=0;i<=entry_count;++i)
    {
        printf("Filling tables key: %08x\n", entry[i]);
        fill_table(countmap[i], entry[i]);
	if (i % 5000 == 0) {
	    sleep(2);
	}
    }

    notify_controller_initialized();
}


int main(int argc, char* argv[])
{
    if (argc>1) {
        if (argc!=2) {
            printf("Too many arguments...\nUsage: %s <filename(optional)>\n", argv[0]);
            return -1;
        }
        printf("Command line argument is present...\nLoading configuration data...\n");
        if (read_entries_from_file(argv[1])<0) {
            printf("File cannnot be opened...\n");
            return -1;
        }
    }

    printf("Create and configure controller...\n");
    c = create_controller_with_init(11111, 3, dhf, init);

    printf("Launching controller's main loop...\n");
    execute_controller(c);

    printf("Destroy controller\n");
    destroy_controller(c);

    return 0;
}

