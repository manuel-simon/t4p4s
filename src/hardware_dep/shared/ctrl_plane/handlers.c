// SPDX-License-Identifier: Apache-2.0
// Copyright 2016 Eotvos Lorand University, Budapest, Hungary

#include "handlers.h"
#include "messages.h"
#include <stdio.h>


int handle_p4_msg(char* buffer, int length, p4_msg_callback cb)
{
	struct p4_header* header;
	struct p4_ctrl_msg ctrl_m;
	int rval = 0;

	if (length<sizeof(struct p4_header)) return -1;

	header = netconv_p4_header((struct p4_header*)buffer);

	if (header->length>length) return -1;
	
	switch (header->type)
	{
		case P4T_SET_DEFAULT_ACTION:
			rval = handle_p4_set_default_action( netconv_p4_set_default_action((struct p4_set_default_action*)buffer), &ctrl_m);
#ifdef T4P4S_DEBUG
			if (rval != 0) {
				printf("[CTRL]    :: SET_DEFAULT_ACTION rval=%d\n", rval);
			}
#endif
			if (rval<0) return rval;
			cb(&ctrl_m);
			break;
		case P4T_MODIFY_TABLE_ENTRY:
			rval = handle_p4_change_table_entry(netconv_p4_change_table_entry((struct p4_change_table_entry*)buffer), &ctrl_m);
#ifdef T4P4S_DEBUG
			if (rval != 0) {
				printf("[CTRL]    :: CHANGE_TABLE_ENTRY rval=%d\n", rval);
			}
#endif
			if (rval<0) return rval;
			cb(&ctrl_m);
			break;
		case P4T_ADD_TABLE_ENTRY:
			rval = handle_p4_add_table_entry(netconv_p4_add_table_entry((struct p4_add_table_entry*)buffer), &ctrl_m);
#ifdef T4P4S_DEBUG
			if (rval != 0) {
				printf("[CTRL]    :: ADD_TABLE_ENTRY rval=%d\n", rval);
			}
#endif
			if (rval<0) return rval;
			cb(&ctrl_m);
			break;
		case P4T_CTRL_INITIALIZED:
			/* no need to inspect trailing bytes if any so just ignore it */
			rval = handle_p4_ctrl_initialized(header, &ctrl_m);
			cb(&ctrl_m);
			break;
		default:
#ifdef T4P4S_DEBUG
			printf("[CTRL] Warning: skippin message of unknown type %d\n", header->type);
#endif
			cb(&ctrl_m);
			return -100;
	}

	return 0;
}

int handle_p4_ctrl_initialized(struct p4_header* header, struct p4_ctrl_msg* ctrl_m)
{
	ctrl_m->type = header->type;
	ctrl_m->xid = header->xid;
	return 0;
}

int handle_p4_set_default_action(struct p4_set_default_action* m, struct p4_ctrl_msg* ctrl_m)
{
	int i;
	int num_params;
	uint16_t offset = 0;
	char* buffer = 0;

	ctrl_m->type = m->header.type;
	ctrl_m->xid = m->header.xid;
	ctrl_m->table_name = m->table_name;
	ctrl_m->action_type = m->action.description.type;
	ctrl_m->action_name = m->action.description.name;
	num_params = m->action.param_size;
	buffer = (char*)(m) + sizeof(struct p4_set_default_action);

	if (num_params>P4_MAX_NUMBER_OF_ACTION_PARAMETERS)
		return -1;	/*Too much arguments*/
	
	ctrl_m->num_action_params = num_params;

	for (i=0;i<num_params;++i)
	{
		ctrl_m->action_params[i] = netconv_p4_action_parameter(unpack_p4_action_parameter(buffer, offset));
		offset += sizeof(struct p4_action_parameter);
	}

	return 0;
}

int handle_p4_change_table_entry(struct p4_change_table_entry* m, struct p4_ctrl_msg* ctrl_m)
{
        int i;
        int num_params;
	int size;
        uint16_t offset = 0;
        char* buffer = 0;
	struct p4_action* action;

        ctrl_m->type = m->header.type;
        ctrl_m->xid = m->header.xid;
        ctrl_m->table_name = m->table_name;
	num_params = m->read_size;
	
	if (num_params>P4_MAX_NUMBER_OF_FIELD_MATCHES)
		return -1; /*Too much field matching rules*/

	ctrl_m->num_field_matches = num_params;

	buffer = (char*)(m) + sizeof(struct p4_add_table_entry);
	offset = 0;

	for (i=0;i<num_params;++i)
	{
		ctrl_m->field_matches[i] = netconv_p4_field_match_complex(unpack_p4_field_match_header(buffer, offset),&size);
		offset += size; /*sizeof(struct p4_field_match_header);*/
	}

	action = unpack_p4_action(buffer, offset);

        ctrl_m->action_type = action->description.type;
        ctrl_m->action_name = action->description.name;
        num_params = action->param_size;
        offset += sizeof(struct p4_action);

        if (num_params>P4_MAX_NUMBER_OF_ACTION_PARAMETERS)
                return -2;      /*Too much arguments*/

	ctrl_m->num_action_params = num_params;

        for (i=0;i<num_params;++i)
        {
                ctrl_m->action_params[i] = netconv_p4_action_parameter(unpack_p4_action_parameter(buffer, offset));
                offset += sizeof(struct p4_action_parameter);
        }

        return 0;
}
int handle_p4_add_table_entry(struct p4_add_table_entry* m, struct p4_ctrl_msg* ctrl_m)
{
        int i;
        int num_params;
	int size;
        uint16_t offset = 0;
        char* buffer = 0;
	struct p4_action* action;

        ctrl_m->type = m->header.type;
        ctrl_m->xid = m->header.xid;
        ctrl_m->table_name = m->table_name;
	num_params = m->read_size;
	
	if (num_params>P4_MAX_NUMBER_OF_FIELD_MATCHES)
		return -1; /*Too much field matching rules*/

	ctrl_m->num_field_matches = num_params;

	buffer = (char*)(m) + sizeof(struct p4_add_table_entry);
	offset = 0;

	for (i=0;i<num_params;++i)
	{
		ctrl_m->field_matches[i] = netconv_p4_field_match_complex(unpack_p4_field_match_header(buffer, offset),&size);
		offset += size; /*sizeof(struct p4_field_match_header);*/
	}

	action = unpack_p4_action(buffer, offset);

        ctrl_m->action_type = action->description.type;
        ctrl_m->action_name = action->description.name;
        num_params = action->param_size;
        offset += sizeof(struct p4_action);

        if (num_params>P4_MAX_NUMBER_OF_ACTION_PARAMETERS)
                return -2;      /*Too much arguments*/

	ctrl_m->num_action_params = num_params;

        for (i=0;i<num_params;++i)
        {
                ctrl_m->action_params[i] = netconv_p4_action_parameter(unpack_p4_action_parameter(buffer, offset));
                offset += sizeof(struct p4_action_parameter);
        }

        return 0;
}
