// SPDX-License-Identifier: Apache-2.0
// Copyright 2016 Eotvos Lorand University, Budapest, Hungary

#include "controller.h"
#include "messages.h"
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

#define MAX_ENTRIES 10

#define SINGLE 0
#define MULTIPLE 1
#define PERIODIC 2

controller c;

static uint32_t number_params[] = { 3, 4, 3};
static char *action_names[] = { "single", "multiple", "periodic"};
static char *param_names[] = {"time", "id", "count"};

extern void notify_controller_initialized();

uint32_t actions[MAX_ENTRIES];
uint32_t keys[MAX_ENTRIES];
uint32_t parammap[MAX_ENTRIES][3];

int entry_count = -1;

void fill_table(uint32_t action, uint32_t key, uint32_t params[])
{
    char buffer[2048];
    struct p4_header* h;
    struct p4_add_table_entry* te;
    struct p4_action* a;
    struct p4_action_parameter* ap[number_params[action]];
    // struct p4_field_match_header* fmh;
    struct p4_field_match_exact* exact;

    h = create_p4_header(buffer, 0, 2048);
    te = create_p4_add_table_entry(buffer,0,2048);
    strcpy(te->table_name, "set_timer_0");

    exact = add_p4_field_match_exact(te, 2048);
    strcpy(exact->header.name, "ipv4.protocol");
    memcpy(exact->bitmap, &key, sizeof(uint32_t));
    exact->length = sizeof(uint32_t)*8+0;



    a = add_p4_action(h, 2048);
    strcpy(a->description.name, action_names[action]);

    for (uint32_t i = 0; i < number_params[action]; i++) {
        ap[i] = add_p4_action_parameter(h, a, 2048);
        strcpy(ap[i]->name, param_names[action]);
        memcpy(ap[i]->bitmap, &params[i], (sizeof(uint32_t)));
        ap[i]->length = (sizeof(uint32_t)) * 8;
    }

    netconv_p4_header(h);
    netconv_p4_add_table_entry(te);
    netconv_p4_field_match_exact(exact);
    netconv_p4_action(a);
    
    for (uint32_t i = 0; i < number_params[action]; i++) {
	    netconv_p4_action_parameter(ap[i]);
    }

    send_p4_msg(c, buffer, 2048);
}




void dhf(void* b) {
    struct p4_header* h = netconv_p4_header(unpack_p4_header(b, 0));
    if (h->type != P4T_DIGEST) {
        printf("Method is not implemented\n");
        return;
    }

    struct p4_digest* d = unpack_p4_digest(b,0);
    printf("Unknown digest received: X%sX\n", d->field_list_name);
}

void set_default_action_set_timer()
{
    char buffer[2048];
    struct p4_header* h;
    struct p4_set_default_action* sda;
    struct p4_action* a;

    printf("Generate set_default_action message for table set_timer\n");

    h = create_p4_header(buffer, 0, sizeof(buffer));

    sda = create_p4_set_default_action(buffer,0,sizeof(buffer));
    strcpy(sda->table_name, "set_timer_0");

    a = &(sda->action);
    strcpy(a->description.name, "_drop");

    netconv_p4_header(h);
    netconv_p4_set_default_action(sda);
    netconv_p4_action(a);

    send_p4_msg(c, buffer, sizeof(buffer));
}

int read_entries_from_file(char *filename) {
    FILE *f;
    char line[200];
    uint32_t key;
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
	    uint32_t c;
	    i = 0;
	    if (ptr != NULL) {
		    if (strcmp(ptr, "SINGLE") == 0) {
		        actions[entry_count] = SINGLE;
		    } else if (strcmp(ptr, "MULTIPLE") == 0) {
	                actions[entry_count] = MULTIPLE;
		    } else if (strcmp(ptr, "PERIODIC") == 0) {
		        actions[entry_count] = PERIODIC;
		    } else {
		        printf("Invalid action name..\n");
		        break;
		    }
		    ptr = strtok(NULL, " ");
	    }

	    if (ptr != NULL) {
		    sscanf(ptr, "%d", &c);
		    ptr = strtok(NULL, " ");
		    keys[entry_count] = (uint32_t) c;
	    }

	    while(ptr != NULL) {
		    sscanf(ptr, "%d", &c);
		    ptr = strtok(NULL, " ");
		    if (i >= number_params[actions[entry_count]]) {
    		    printf("Too many args...\n");
    		    break;
    		}
	    	    parammap[entry_count][i++] = (uint32_t) c;
    	    }

    	    entry_count++;
    }

    fclose(f);
    return 0;
}

void init() {
    int i;
    printf("Set default actions.\n");
    set_default_action_set_timer();

    for (i=0;i<=entry_count;++i)
    {
        printf("Filling tables with action %s and key %i\n", action_names[actions[i]], keys[i]);
        fill_table(actions[i], keys[i], parammap[i]);
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

