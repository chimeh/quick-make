/****************************************************************************
 * ctc_cmd.h :         header
 *
 * Copyright (C) 2010 Centec Networks Inc.  All rights reserved.
 *
 * Modify History :
 * Revision       :         V1.0
 * Date           :         2010-7-28
 * Reason         :         First Create
 ****************************************************************************/

#include "sal/core/libc.h"
#include "sal/core/alloc.h"
#include "ctc_types.h"
#include "ctc_sal.h"
#ifdef SDK_IN_KERNEL
#include <linux/kernel.h>
#endif
#include "ctc_cli.h"
#include "ctc_cmd.h"

#define MAX_OPTIONAL_CMD_NUM 100 /* max optional cmd number in {} */

/* Command vector which includes some level of command lists. Normally
   each daemon maintains each own cmdvec. */
vector cmdvec;
int32 cmd_debug = 0;
int32 cmd_arg_debug = 0;
ctc_cmd_desc_t** matched_desc_ptr  = NULL;

#define CHAR_BIT 8
#define STACK_SIZE	(CHAR_BIT * sizeof(size_t))
#define PUSH(low, high)	((top->lo = (low)), (top->hi = (high)), ++top)
#define	POP(low, high)	(--top, (low = top->lo), (high = top->hi))
#define	STACK_NOT_EMPTY	(stack < top)
#define MAX_THRESH 4
/* Stack node declarations used to store unfulfilled partition obligations. */
typedef struct {
	char *lo;
	char *hi;
} stack_node;
#define SWAP(a, b, size)		      \
  do {					      \
      size_t __size = (size);		      \
      char *__a = (a), *__b = (b);	      \
      do {				      \
	  char __tmp = *__a;		      \
	  *__a++ = *__b;		      \
	  *__b++ = __tmp;		      \
	} while (--__size > 0);		      \
    } while (0)
void
sal_qsort(void *const pbase, size_t total_elems, size_t size,
      int (*cmp)(const void*, const void*))
{

	char *base_ptr = (char *)pbase;

	const size_t max_thresh = MAX_THRESH * size;

	/* Avoid lossage with unsigned arithmetic below.  */
	if (total_elems == 0) {
		return;
	}

	if (total_elems > MAX_THRESH) {
		char *lo = base_ptr;
		char *hi = &lo[size * (total_elems - 1)];
		stack_node stack[STACK_SIZE];
		stack_node *top = stack + 1;

		while (STACK_NOT_EMPTY) {
			char *left_ptr;
			char *right_ptr;

			/* Select median value from among LO, MID, and
			   HI. Rearrange LO and HI so the three values
			   are sorted. This lowers the probability of
			   picking a pathological pivot value and
			   skips a comparison for both the LEFT_PTR
			   and RIGHT_PTR in the while loops. */

			char *mid = lo + size * ((hi - lo) / size >> 1);

			if ((*cmp)((void*)mid, (void*)lo) < 0)
				SWAP(mid, lo, size);
			if ((*cmp)((void*)hi, (void*)mid) < 0)
				SWAP(mid, hi, size);
			else
				goto jump_over;
			if ((*cmp)((void*)mid, (void*)lo) < 0)
				SWAP(mid, lo, size);
		jump_over:

			left_ptr = lo + size;
			right_ptr = hi - size;

			/* Here's the famous ``collapse the walls''
			   section of quicksort.  Gotta like those
			   tight inner loops!  They are the main
			   reason that this algorithm runs much faster
			   than others. */
			do {
				while ((*cmp)((void*)left_ptr, (void*)mid) < 0)
					left_ptr += size;

				while ((*cmp)((void*)mid, (void*)right_ptr) < 0)
					right_ptr -= size;

				if (left_ptr < right_ptr) {
					SWAP(left_ptr, right_ptr, size);
					if (mid == left_ptr)
						mid = right_ptr;
					else if (mid == right_ptr)
						mid = left_ptr;
					left_ptr += size;
					right_ptr -= size;
				} else if (left_ptr == right_ptr) {
					left_ptr += size;
					right_ptr -= size;
					break;
				}
			}
			while (left_ptr <= right_ptr);

			/* Set up pointers for next iteration.  First
			   determine whether left and right partitions
			   are below the threshold size.  If so,
			   ignore one or both.  Otherwise, push the
			   larger partition's bounds on the stack and
			   continue sorting the smaller one. */

			if ((size_t) (right_ptr - lo) <= max_thresh) {
				if ((size_t) (hi - left_ptr) <= max_thresh)
					/* Ignore both small partitions. */
					POP(lo, hi);
				else
					/* Ignore small left partition. */
					lo = left_ptr;
			} else if ((size_t) (hi - left_ptr) <= max_thresh)
				/* Ignore small right partition. */
				hi = right_ptr;
			else if ((right_ptr - lo) > (hi - left_ptr)) {
				/* Push larger left partition indices. */
				PUSH(lo, right_ptr);
				lo = left_ptr;
			} else {
				/* Push larger right partition indices. */
				PUSH(left_ptr, hi);
				hi = right_ptr;
			}
		}
	}

	/* Once the BASE_PTR array is partially sorted by quicksort
	   the rest is completely sorted using insertion sort, since
	   this is efficient for partitions below MAX_THRESH
	   size. BASE_PTR points to the beginning of the array to
	   sort, and END_PTR points at the very last element in the
	   array (*not* one beyond it!). */

	{
		char *end_ptr = &base_ptr[size * (total_elems - 1)];
		char *tmp_ptr = base_ptr;
		char *thresh = min(end_ptr, base_ptr + max_thresh);
		char *run_ptr;

		/* Find smallest element in first threshold and place
		   it at the array's beginning.  This is the smallest
		   array element, and the operation speeds up
		   insertion sort's inner loop. */

		for (run_ptr = tmp_ptr + size; run_ptr <= thresh; run_ptr += size)
			if ((*cmp)((void*)run_ptr, (void*)tmp_ptr) < 0)
				tmp_ptr = run_ptr;

		if (tmp_ptr != base_ptr)
			SWAP(tmp_ptr, base_ptr, size);

		/* Insertion sort, running from left-hand-side up to
		 * right-hand-side.  */

		run_ptr = base_ptr + size;
		while ((run_ptr += size) <= end_ptr) {
			tmp_ptr = run_ptr - size;
			while ((*cmp)((void*)run_ptr, (void*)tmp_ptr) < 0)
				tmp_ptr -= size;

			tmp_ptr += size;
			if (tmp_ptr != run_ptr) {
				char *trav;

				trav = run_ptr + size;
				while (--trav >= run_ptr) {
					char c = *trav;
					char *hi, *lo;

					for (hi = lo = trav; (lo -= size) >= tmp_ptr; hi = lo)
						*hi = *lo;
					*hi = c;
				}
			}
		}
	}
}
best_match_type_t
ctc_cmd_best_match_check(vector vline, ctc_cmd_desc_t** matched_desc_ptr, int32 if_describe)
{
    int32 i = 0;
    char* command = NULL;
    char* str = NULL;
    ctc_cmd_desc_t* matched_desc = NULL;
    int32 max_index = vector_max(vline);

    if (if_describe)
    {
        max_index--;
    }

    for (i = 0; i < max_index; i++)
    {
        command = vector_slot(vline, i);
        matched_desc = matched_desc_ptr[i];
        if (command && command[0] >= 'a' && command[0] <= 'z') /* keyword format*/
        {
            str = matched_desc->cmd;
            if (CTC_CMD_VARIABLE(str))
            {
                return CTC_CMD_EXTEND_MATCH; /* extend match */
            }

            if (sal_strncmp(command, str, sal_strlen(command)) == 0)
            {
                if (sal_strcmp(command, str) == 0) /* exact match */
                {
                    continue;
                }
                else
                {
                    return CTC_CMD_PARTLY_MATCH; /* partly match */
                }
            }
        }
    }

    return CTC_CMD_EXACT_MATCH; /* exact match */
}

char*
ctc_strdup(char* str)
{
    char* new_str = sal_alloc(sal_strlen(str) + 1, "clicmd");

    if (new_str)
    {
        sal_memcpy(new_str, str, sal_strlen(str) + 1);
    }

    return new_str;
}

/* Install top node of command vector. */
void
ctc_install_node(ctc_cmd_node_t* node, int32 (* func)(ctc_vti_t*))
{
    ctc_vti_vec_set_index(cmdvec, node->node, node);
    node->func = func;
    node->cmd_vector = ctc_vti_vec_init(VECTOR_MIN_SIZE);
    if (!node->cmd_vector)
    {
        ctc_cli_out("System error: no memory for install node!\n\r");
    }
}

/* Compare two command's string.  Used in ctc_sort_node (). */
int32
ctc_cmp_node(const void* p, const void* q)
{
    ctc_cmd_element_t* a = *(ctc_cmd_element_t**)p;
    ctc_cmd_element_t* b = *(ctc_cmd_element_t**)q;

    return sal_strcmp(a->string, b->string);
}

/* Sort each node's command element according to command string. */
void
ctc_sort_node()
{
    int32 i;
    /* int32 j;*/
    ctc_cmd_node_t* cnode;

    /*vector descvec;*/
    /*ctc_cmd_element_t *cmd_element;*/

    for (i = 0; i < vector_max(cmdvec); i++)
    {
        if ((cnode = vector_slot(cmdvec, i)) != NULL)
        {
            vector cmd_vector = cnode->cmd_vector;
            sal_qsort(cmd_vector->index, cmd_vector->max, sizeof(void*), ctc_cmp_node);
        }
    }
}

/* Breaking up string into each command piece. I assume given
   character is separated by a space character. Return value is a
   vector which includes char ** data element. */
vector
ctc_cmd_make_strvec(char* string)
{
    char* cp, * start, * token;
    int32 strlen;
    vector strvec;

    if (string == NULL)
    {
        return NULL;
    }

    cp = string;

    /* Skip white spaces. */
    while (sal_isspace((int32) * cp) && *cp != '\0')
    {
        cp++;
    }

    /* Return if there is only white spaces */
    if (*cp == '\0')
    {
        return NULL;
    }

    if (*cp == '!' || *cp == '#')
    {
        return NULL;
    }

    /* Prepare return vector. */
    strvec = ctc_vti_vec_init(VECTOR_MIN_SIZE);
    if (!strvec)
    {
        return NULL;
    }

    /* Copy each command piece and set into vector. */
    while (1)
    {
        start = cp;

        while (!(sal_isspace((int32) * cp) || *cp == '\r' || *cp == '\n') && *cp != '\0')
        {
            cp++;
        }

        strlen = cp - start;
        token = sal_alloc(strlen + 1, "clicmd");
        sal_memcpy(token, start, strlen);
        *(token + strlen) = '\0';
        ctc_vti_vec_set(strvec, token);

        while ((sal_isspace((int32) * cp) || *cp == '\n' || *cp == '\r') && *cp != '\0')
        {
            cp++;
        }

        if (*cp == '\0')
        {
            return strvec;
        }
    }
}

/* Free allocated string vector. */
void
ctc_cmd_free_strvec(vector v)
{
    int32 i;
    char* cp;

    if (!v)
    {
        return;
    }

    for (i = 0; i < vector_max(v); i++)
    {
        if ((cp = vector_slot(v, i)) != NULL)
        {
            sal_free(cp);
        }
    }

    ctc_vti_vec_free(v);
}

/* Fetch next description.  Used in ctc_cmd_make_descvec(). */
char*
ctc_cmd_desc_str(char** string)
{
    char* cp, * start, * token;
    int32 strlen;

    cp = *string;

    if (cp == NULL)
    {
        return NULL;
    }

    /* Skip white spaces. */
    while (sal_isspace((int32) * cp) && *cp != '\0')
    {
        cp++;
    }

    /* Return if there is only white spaces */
    if (*cp == '\0')
    {
        return NULL;
    }

    start = cp;

    while (!(*cp == '\r' || *cp == '\n') && *cp != '\0')
    {
        cp++;
    }

    strlen = cp - start;
    token = sal_alloc(strlen + 1, "clicmd");
    sal_memcpy(token, start, strlen);
    *(token + strlen) = '\0';

    *string = cp;

    return token;
}

char*
cmd_parse_token(char** cp, cmd_token_type* token_type)
{
    char* sp = NULL;
    char* token = NULL;
    int32 len = 0;
    int32 need_while = 1;

    if (**cp == '\0')
    {
        *token_type = cmd_token_unknown;
        return NULL;
    }

    while (**cp != '\0' && need_while)
    {
        switch (**cp)
        {
        case ' ':
            (*cp)++;
            ;
            break;

        case '{':
            (*cp)++;
            *token_type = cmd_token_cbrace_open;
            return NULL;

        case '(':
            (*cp)++;
            *token_type = cmd_token_paren_open;
            return NULL;

        case '|':
            (*cp)++;
            *token_type = cmd_token_separator;
            return NULL;

        case ')':
            (*cp)++;
            *token_type = cmd_token_paren_close;
            return NULL;

        case '}':
            (*cp)++;
            *token_type = cmd_token_cbrace_close;
            return NULL;

        case '\n':
            (*cp)++;
            break;

        case '\r':
            (*cp)++;
            break;

        default:
            need_while = 0;
            break;
        }
    }

    sp = *cp;

    while (!(**cp == ' ' || **cp == '\r' || **cp == '\n' || **cp == ')' || **cp == '(' || **cp == '{' || **cp == '}' || **cp == '|') && **cp != '\0')
    {
        (*cp)++;
    }

    len = *cp - sp;

    if (len)
    {
        token = sal_alloc(len + 1, "clicmd");
        sal_memcpy(token, sp, len);
        *(token + len) = '\0';
        if (CTC_CMD_VARIABLE(token))
        {
            *token_type = cmd_token_var;
        }
        else
        {
            *token_type = cmd_token_keyword;
        }

        return token;
    }

    *token_type = cmd_token_unknown;
    return NULL;
}

vector
cmd_make_cli_tree(ctc_cmd_desc_t* tmp_desc, char** descstr, vector parent, int32* dp_index, int32 depth)
{
    cmd_token_type token_type = 0;

    char* token = NULL;
    vector cur_vec = NULL;
    vector pending_vec = NULL;
    vector sub_parent_vec = NULL;
    ctc_cmd_desc_t* desc = NULL;
    int32 flag = 0;
    vector p = NULL;

    while (*(tmp_desc->str) != '\0')
    {
        token = cmd_parse_token(&tmp_desc->str, &token_type);

        switch (token_type)
        {
        case cmd_token_paren_open:
            cur_vec = ctc_vti_vec_init(VECTOR_MIN_SIZE);
            cur_vec->is_desc = 0;
            cur_vec->is_multiple = 0;
            cur_vec->direction = 0;
            if (flag)    /* '(' after '|', finish previous building */
            {
                flag++;
                if (flag == 2)  /* flag==2 first keyword or VAR after seperator */
                {
                    pending_vec = cur_vec;
                }
                else if (flag == 3)  /* 2 words are after seperator, current and pending vectors belong to sub_parent_vec */
                {
                    sub_parent_vec = ctc_vti_vec_init(VECTOR_MIN_SIZE);
                    ctc_vti_vec_set(sub_parent_vec, pending_vec);
                    ctc_vti_vec_set(sub_parent_vec, cur_vec);
                    ctc_vti_vec_set(parent, sub_parent_vec);
                }
                else    /* 2 more words are after seperator */
                {
                    ctc_vti_vec_set(sub_parent_vec, cur_vec);     /* all more vectors belong to sub_parent_vec */
                }
            }
            else
            {
                ctc_vti_vec_set(parent, cur_vec);
            }

            cmd_make_cli_tree(tmp_desc, descstr, cur_vec, dp_index, depth + 1);
            cur_vec = NULL;
            break;

        case cmd_token_cbrace_open:
            cur_vec = ctc_vti_vec_init(VECTOR_MIN_SIZE);
            cur_vec->is_desc = 0;
            cur_vec->is_multiple = 1;     /* this is difference for {} and(), other codes are same */
            cur_vec->direction = 0;
            if (flag)
            {
                flag++;
                if (flag == 2)
                {
                    pending_vec = cur_vec;
                }
                else if (flag == 3)
                {
                    sub_parent_vec = ctc_vti_vec_init(VECTOR_MIN_SIZE);
                    ctc_vti_vec_set(sub_parent_vec, pending_vec);
                    ctc_vti_vec_set(sub_parent_vec, cur_vec);
                    ctc_vti_vec_set(parent, sub_parent_vec);
                }
                else
                {
                    ctc_vti_vec_set(sub_parent_vec, cur_vec);
                }
            }
            else
            {
                ctc_vti_vec_set(parent, cur_vec);
            }

            cmd_make_cli_tree(tmp_desc, descstr, cur_vec, dp_index, depth + 1);
            cur_vec = NULL;
            break;

        case cmd_token_paren_close:
        case cmd_token_cbrace_close:
            if (flag == 1)
            {
                parent->is_option = 1;
            }
            else if (flag == 2)  /* flag==2 first keyword after seperator, only one keyword  */
            {
                ctc_vti_vec_set(parent, pending_vec);
            }

            flag = 0;
            return parent;
            break;

        case cmd_token_separator:
            if (!parent->direction && (ctc_vti_vec_count(parent) > 1)) /* if current parent is tranverse and has more than 2 vector, make it a sub parent*/
            {
                p = ctc_vti_vec_copy(parent);
                sal_memset(parent->index, 0, sizeof(void*) * parent->max);
                vector_reset(parent);
                ctc_vti_vec_set(parent, p);
            }

            parent->direction = 1;
            if (flag == 2)    /* new seperator starts, finish previous */
            {
                ctc_vti_vec_set(parent, pending_vec);
            }

            flag = 1;     /*flag=1, new seperator starts*/
            cur_vec = NULL;
            break;

        case cmd_token_keyword:
            if (!cur_vec)
            {
                cur_vec = ctc_vti_vec_init(VECTOR_MIN_SIZE);
                cur_vec->direction = 0;
                cur_vec->is_multiple = 0;
                cur_vec->is_desc = 1;

                if (flag)
                {
                    flag++;
                    if (flag == 2)  /* flag==2 first keyword or VAR after seperator */
                    {
                        pending_vec = cur_vec;
                    }
                    else if (flag == 3)  /* flag==3 seconds keyword or VAR after seperator */
                    {
                        sub_parent_vec = ctc_vti_vec_init(VECTOR_MIN_SIZE);
                        ctc_vti_vec_set(sub_parent_vec, pending_vec);
                        ctc_vti_vec_set(sub_parent_vec, cur_vec);
                        ctc_vti_vec_set(parent, sub_parent_vec);
                    }
                    else     /* flag>3, more keywords */
                    {
                        ctc_vti_vec_set(sub_parent_vec, cur_vec);
                    }
                }
                else
                {
                    ctc_vti_vec_set(parent, cur_vec);
                }
            }

            desc = sal_alloc(sizeof(ctc_cmd_desc_t), "clicmd");
            sal_memset(desc, 0, sizeof(ctc_cmd_desc_t));
            desc->cmd = token;
            desc->str = descstr[*dp_index];
            if (depth > 0)
            {
                desc->is_arg = 1;
            }
            else
            {
                desc->is_arg = 0;
            }

            (*dp_index)++;

            ctc_vti_vec_set(cur_vec, desc);
            break;

        case cmd_token_var:
            if (!cur_vec)
            {
                cur_vec = ctc_vti_vec_init(VECTOR_MIN_SIZE);
                cur_vec->direction = 0;
                cur_vec->is_multiple = 0;
                cur_vec->is_desc = 1;

                if (flag)    /* deal with seperator */
                {
                    flag++;
                    if (flag == 2)  /* flag==2 first keyword or VAR after seperator */
                    {
                        pending_vec = cur_vec;
                    }
                    else if (flag == 3)  /* flag==3 seconds keyword or VAR after seperator */
                    {
                        sub_parent_vec = ctc_vti_vec_init(VECTOR_MIN_SIZE);
                        ctc_vti_vec_set(sub_parent_vec, pending_vec);
                        ctc_vti_vec_set(sub_parent_vec, cur_vec);
                        ctc_vti_vec_set(parent, sub_parent_vec);
                    }
                    else     /* flag>3, more keywords or VAR */
                    {
                        ctc_vti_vec_set(sub_parent_vec, cur_vec);
                    }
                }
                else
                {
                    ctc_vti_vec_set(parent, cur_vec);
                }
            }

            desc = sal_alloc(sizeof(ctc_cmd_desc_t), "clicmd");
            sal_memset(desc, 0, sizeof(ctc_cmd_desc_t));
            desc->cmd = token;
            desc->str = descstr[*dp_index];
            desc->is_arg = 1;
            (*dp_index)++;

            ctc_vti_vec_set(cur_vec, desc);
            break;

        default:
            break;
        }
    }

    return parent;
}

vector
ctc_cmd_make_descvec(char* string, char** descstr)
{
    vector all_vec = NULL;
    int32 dp_index = 0;
    ctc_cmd_desc_t tmp_desc;

    tmp_desc.str = string;

    if (string == NULL)
    {
        return NULL;
    }

    all_vec = ctc_vti_vec_init(VECTOR_MIN_SIZE);
    all_vec->is_desc = 0;
    all_vec->direction = 0;
    all_vec->is_multiple = 0;

    return cmd_make_cli_tree(&tmp_desc, descstr, all_vec, &dp_index, 0);
}

void
cmd_dump_vector_tree(vector all_vec, int32 depth)
{
    vector cur_vec = NULL;
    int32 i = 0;
    int32 j = 0;
    int32 space = 0;
    ctc_cmd_desc_t* desc;

    for (i = 0; i < vector_max(all_vec); i++)
    {
        cur_vec = vector_slot(all_vec, i);

        for (space = 0; space < depth; space++)
        {
            ctc_cli_out("  ");
        }

        ctc_cli_out("%d:", i);
        if (cur_vec->direction)
        {
            ctc_cli_out("V:");
        }
        else
        {
            ctc_cli_out("T:");
        }

        if (cur_vec->is_desc)
        {
            ctc_cli_out("s:");
        }
        else
        {
            ctc_cli_out("v:");
        }

        ctc_cli_out("\n\r");

        if (cur_vec->is_desc)
        {
            for (space = 0; space < depth; space++)
            {
                ctc_cli_out("  ");
            }

            for (j = 0; j < vector_max(cur_vec); j++)
            {
                desc = vector_slot(cur_vec, j);
                /*ctc_cli_out("  %s [%s] ", desc->cmd, desc->str);*/
                ctc_cli_out("  %s ", desc->cmd);
            }

            ctc_cli_out("\n\r");
        }
        else
        {
            cmd_dump_vector_tree(cur_vec, depth + 1);
        }
    }
}

/* Count mandantory string vector size.  This is to determine inputed
   command has enough command length. */
int32
ctc_cmd_cmdsize(vector strvec)
{
    int32 i;
    int32 size = 0;
    vector descvec;

    for (i = 0; i < vector_max(strvec); i++)
    {
        descvec = vector_slot(strvec, i);
    }

    return size;
}

/* Return prompt character of specified node. */
char*
ctc_cmd_prompt(ctc_node_type_t node)
{
    ctc_cmd_node_t* cnode;

    cnode = vector_slot(cmdvec, node);
    return cnode->prompt;
}

ctc_cmd_desc_t*
cmd_get_desc(vector strvec, int32 index, int32 depth)
{
    vector descvec;

    if (index >= vector_max(strvec))
    {
        return NULL;
    }

    descvec = vector_slot(strvec, index);
    if (!descvec)
    {
        return NULL;
    }

    if (depth >= vector_max(descvec))
    {
        return NULL;
    }

    return vector_slot(descvec, depth);
}

/* Install a command into a node. */
void
install_element(ctc_node_type_t ntype, ctc_cmd_element_t* cmd)
{
    ctc_cmd_node_t* cnode;

    cnode = vector_slot(cmdvec, ntype);

    if (cnode == NULL)
    {
        ctc_cli_out("Command node %d doesn't exist, please check it\n", ntype);
        return;
    }

    ctc_vti_vec_set(cnode->cmd_vector, cmd);

    cmd->strvec = ctc_cmd_make_descvec(cmd->string, cmd->doc);
    cmd->cmdsize = ctc_cmd_cmdsize(cmd->strvec);

    if (cmd_debug)
    {
        ctc_cli_out("cmdsize=%d for cmd: %s\n\r", cmd->cmdsize, cmd->string);
        if (cmd->strvec->direction)
        {
            ctc_cli_out("Parent V\n\r");
        }
        else
        {
            ctc_cli_out("Parent T\n\r");
        }

        cmd_dump_vector_tree(cmd->strvec, 0);
    }
}

/* Utility function for getting command vector. */
vector
ctc_cmd_node_vector(vector v, ctc_node_type_t ntype)
{
    ctc_cmd_node_t* cnode = vector_slot(v, ntype);

    return cnode->cmd_vector;
}

/* Filter command vector by symbol */
int32
ctc_cmd_filter_by_symbol(char* command, char* symbol)
{
    int32 i, lim;

    if (sal_strcmp(symbol, "IPV4_ADDRESS") == 0)
    {
        i = 0;
        lim = sal_strlen(command);

        while (i < lim)
        {
            if (!(sal_isdigit((int32)command[i]) || command[i] == '.' || command[i] == '/'))
            {
                return 1;
            }

            i++;
        }

        return 0;
    }

    if (sal_strcmp(symbol, "STRING") == 0)
    {
        i = 0;
        lim = sal_strlen(command);

        while (i < lim)
        {
            if (!(sal_isalpha((int32)command[i]) || command[i] == '_' || command[i] == '-'))
            {
                return 1;
            }

            i++;
        }

        return 0;
    }

    if (sal_strcmp(symbol, "IFNAME") == 0)
    {
        i = 0;
        lim = sal_strlen(command);

        while (i < lim)
        {
            if (!sal_isalnum((int32)command[i]))
            {
                return 1;
            }

            i++;
        }

        return 0;
    }

    return 0;
}

ctc_match_type_t
ctc_cmd_CTC_IPV4_MATCH(char* str)
{
    char* sp;
    int32 dots = 0, nums = 0;
    char buf[4];

    if (str == NULL)
    {
        return CTC_PARTLY_MATCH;
    }

    for (;;)
    {
        sal_memset(buf, 0, sizeof(buf));
        sp = str;

        while (*str != '\0')
        {
            if (*str == '.')
            {
                if (dots >= 3)
                {
                    return CTC_CTC_NO_MATCH;
                }

                if (*(str + 1) == '.')
                {
                    return CTC_CTC_NO_MATCH;
                }

                if (*(str + 1) == '\0')
                {
                    return CTC_PARTLY_MATCH;
                }

                dots++;
                break;
            }

            if (!sal_isdigit((int32) * str))
            {
                return CTC_CTC_NO_MATCH;
            }

            str++;
        }

        if (str - sp > 3)
        {
            return CTC_CTC_NO_MATCH;
        }

        sal_strncpy(buf, sp, str - sp);
        if (sal_strtos32(buf, NULL, 10) > 255)
        {
            return CTC_CTC_NO_MATCH;
        }

        nums++;

        if (*str == '\0')
        {
            break;
        }

        str++;
    }

    if (nums < 4)
    {
        return CTC_PARTLY_MATCH;
    }

    return CTC_EXACT_MATCH;
}

ctc_match_type_t
ctc_cmd_CTC_IPV4_PREFIX_MATCH(char* str)
{
    char* sp;
    int32 dots = 0;
    char buf[4];

    if (str == NULL)
    {
        return CTC_PARTLY_MATCH;
    }

    for (;;)
    {
        sal_memset(buf, 0, sizeof(buf));
        sp = str;

        while (*str != '\0' && *str != '/')
        {
            if (*str == '.')
            {
                if (dots == 3)
                {
                    return CTC_CTC_NO_MATCH;
                }

                if (*(str + 1) == '.' || *(str + 1) == '/')
                {
                    return CTC_CTC_NO_MATCH;
                }

                if (*(str + 1) == '\0')
                {
                    return CTC_PARTLY_MATCH;
                }

                dots++;
                break;
            }

            if (!sal_isdigit((int32) * str))
            {
                return CTC_CTC_NO_MATCH;
            }

            str++;
        }

        if (str - sp > 3)
        {
            return CTC_CTC_NO_MATCH;
        }

        sal_strncpy(buf, sp, str - sp);
        if (sal_atoi(buf) > 255)
        {
            return CTC_CTC_NO_MATCH;
        }

        if (dots == 3)
        {
            if (*str == '/')
            {
                if (*(str + 1) == '\0')
                {
                    return CTC_PARTLY_MATCH;
                }

                str++;
                break;
            }
            else if (*str == '\0')
            {
                return CTC_PARTLY_MATCH;
            }
        }

        if (*str == '\0')
        {
            return CTC_PARTLY_MATCH;
        }

        str++;
    }

    sp = str;

    while (*str != '\0')
    {
        if (!sal_isdigit((int32) * str))
        {
            return CTC_CTC_NO_MATCH;
        }

        str++;
    }

    if (sal_strtos32(sp, NULL, 10) > 32)
    {
        return CTC_CTC_NO_MATCH;
    }

    return CTC_EXACT_MATCH;
}

#define IPV6_ADDR_STR       "0123456789abcdefABCDEF:.%"
#define IPV6_PREFIX_STR     "0123456789abcdefABCDEF:.%/"
#define STATE_START         1
#define STATE_COLON         2
#define STATE_DOUBLE        3
#define STATE_ADDR          4
#define STATE_DOT           5
#define STATE_SLASH         6
#define STATE_MASK          7

ctc_match_type_t
ctc_cmd_CTC_IPV6_MATCH(char* str)
{
    int32 state = STATE_START;
    int32 colons = 0, nums = 0, double_colon = 0;
    char* sp = NULL;

    if (str == NULL)
    {
        return CTC_PARTLY_MATCH;
    }

    if (sal_strspn(str, IPV6_ADDR_STR) != sal_strlen(str))
    {
        return CTC_CTC_NO_MATCH;
    }

    while (*str != '\0')
    {
        switch (state)
        {
        case STATE_START:
            if (*str == ':')
            {
                if (*(str + 1) != ':' && *(str + 1) != '\0')
                {
                    return CTC_CTC_NO_MATCH;
                }

                colons--;
                state = STATE_COLON;
            }
            else
            {
                sp = str;
                state = STATE_ADDR;
            }

            continue;

        case STATE_COLON:
            colons++;
            if (*(str + 1) == ':')
            {
                state = STATE_DOUBLE;
            }
            else
            {
                sp = str + 1;
                state = STATE_ADDR;
            }

            break;

        case STATE_DOUBLE:
            if (double_colon)
            {
                return CTC_CTC_NO_MATCH;
            }

            if (*(str + 1) == ':')
            {
                return CTC_CTC_NO_MATCH;
            }
            else
            {
                if (*(str + 1) != '\0')
                {
                    colons++;
                }

                sp = str + 1;
                state = STATE_ADDR;
            }

            double_colon++;
            nums++;
            break;

        case STATE_ADDR:
            if (*(str + 1) == ':' || *(str + 1) == '\0')
            {
                if (str - sp > 3)
                {
                    return CTC_CTC_NO_MATCH;
                }

                nums++;
                state = STATE_COLON;
            }

            if (*(str + 1) == '.')
            {
                state = STATE_DOT;
            }

            break;

        case STATE_DOT:
            state = STATE_ADDR;
            break;

        default:
            break;
        }

        if (nums > 8)
        {
            return CTC_CTC_NO_MATCH;
        }

        if (colons > 7)
        {
            return CTC_CTC_NO_MATCH;
        }

        str++;
    }

#if 0
    if (nums < 11)
    {
        return CTC_PARTLY_MATCH;
    }

#endif /* 0 */

    return CTC_EXACT_MATCH;
}

ctc_match_type_t
ctc_cmd_CTC_IPV6_PREFIX_MATCH(char* str)
{
    int32 state = STATE_START;
    int32 colons = 0, nums = 0, double_colon = 0;
    int32 mask;
    char* sp = NULL;
    char* endptr = NULL;

    if (str == NULL)
    {
        return CTC_PARTLY_MATCH;
    }

    if (sal_strspn(str, IPV6_PREFIX_STR) != sal_strlen(str))
    {
        return CTC_CTC_NO_MATCH;
    }

    while (*str != '\0' && state != STATE_MASK)
    {
        switch (state)
        {
        case STATE_START:
            if (*str == ':')
            {
                if (*(str + 1) != ':' && *(str + 1) != '\0')
                {
                    return CTC_CTC_NO_MATCH;
                }

                colons--;
                state = STATE_COLON;
            }
            else
            {
                sp = str;
                state = STATE_ADDR;
            }

            continue;

        case STATE_COLON:
            colons++;
            if (*(str + 1) == '/')
            {
                return CTC_CTC_NO_MATCH;
            }
            else if (*(str + 1) == ':')
            {
                state = STATE_DOUBLE;
            }
            else
            {
                sp = str + 1;
                state = STATE_ADDR;
            }

            break;

        case STATE_DOUBLE:
            if (double_colon)
            {
                return CTC_CTC_NO_MATCH;
            }

            if (*(str + 1) == ':')
            {
                return CTC_CTC_NO_MATCH;
            }
            else
            {
                if (*(str + 1) != '\0' && *(str + 1) != '/')
                {
                    colons++;
                }

                sp = str + 1;

                if (*(str + 1) == '/')
                {
                    state = STATE_SLASH;
                }
                else
                {
                    state = STATE_ADDR;
                }
            }

            double_colon++;
            nums += 1;
            break;

        case STATE_ADDR:
            if (*(str + 1) == ':' || *(str + 1) == '.'
                || *(str + 1) == '\0' || *(str + 1) == '/')
            {
                if (str - sp > 3)
                {
                    return CTC_CTC_NO_MATCH;
                }

                for (; sp <= str; sp++)
                {
                    if (*sp == '/')
                    {
                        return CTC_CTC_NO_MATCH;
                    }
                }

                nums++;

                if (*(str + 1) == ':')
                {
                    state = STATE_COLON;
                }
                else if (*(str + 1) == '.')
                {
                    state = STATE_DOT;
                }
                else if (*(str + 1) == '/')
                {
                    state = STATE_SLASH;
                }
            }

            break;

        case STATE_DOT:
            state = STATE_ADDR;
            break;

        case STATE_SLASH:
            if (*(str + 1) == '\0')
            {
                return CTC_PARTLY_MATCH;
            }

            state = STATE_MASK;
            break;

        default:
            break;
        }

        if (nums > 11)
        {
            return CTC_CTC_NO_MATCH;
        }

        if (colons > 7)
        {
            return CTC_CTC_NO_MATCH;
        }

        str++;
    }

    if (state < STATE_MASK)
    {
        return CTC_PARTLY_MATCH;
    }

    mask = sal_strtol(str, &endptr, 10);
    if (*endptr != '\0')
    {
        return CTC_CTC_NO_MATCH;
    }

    if (mask < 0 || mask > 128)
    {
        return CTC_CTC_NO_MATCH;
    }

    return CTC_EXACT_MATCH;
}

#define DECIMAL_STRLEN_MAX 10

int32
ctc_cmd_CTC_RANGE_MATCH(char* range, char* str)
{
    char* p;
    char buf[DECIMAL_STRLEN_MAX + 1];
    char* endptr = NULL;
    uint32 min, max, val;

    if (str == NULL)
    {
        return 1;
    }

    val = sal_strtou32(str, &endptr, 10);
    if (*endptr != '\0')
    {
        return 0;
    }

    range++;
    p = sal_strchr(range, '-');
    if (p == NULL)
    {
        return 0;
    }

    if (p - range > DECIMAL_STRLEN_MAX)
    {
        return 0;
    }

    sal_strncpy(buf, range, p - range);
    buf[p - range] = '\0';
    min = sal_strtou32(buf, &endptr, 10);
    if (*endptr != '\0')
    {
        return 0;
    }

    range = p + 1;
    p = sal_strchr(range, '>');
    if (p == NULL)
    {
        return 0;
    }

    if (p - range > DECIMAL_STRLEN_MAX)
    {
        return 0;
    }

    sal_strncpy(buf, range, p - range);
    buf[p - range] = '\0';
    max = sal_strtou32(buf, &endptr, 10);
    if (*endptr != '\0')
    {
        return 0;
    }

    if (val < min || val > max)
    {
        return 0;
    }

    return 1;
}

/* Filter vector by command character with index. */
ctc_match_type_t
ctc_cmd_filter_by_string(char* command, vector v, int32 index)
{
    int32 i;
    char* str;
    ctc_cmd_element_t* cmd_element;
    ctc_match_type_t match_type;
    vector descvec;
    ctc_cmd_desc_t* desc;

    match_type = CTC_CTC_NO_MATCH;

    /* If command and cmd_element string does not match set NULL to vector */
    for (i = 0; i < vector_max(v); i++)
    {
        if ((cmd_element = vector_slot(v, i)) != NULL)
        {
            /* If given index is bigger than max string vector of command,
            set NULL*/
            if (index >= vector_max(cmd_element->strvec))
            {
                vector_slot(v, i) = NULL;
            }
            else
            {
                int32 j;
                int32 matched = 0;

                descvec = vector_slot(cmd_element->strvec, index);

                for (j = 0; j < vector_max(descvec); j++)
                {
                    desc = vector_slot(descvec, j);
                    str = desc->cmd;

                    if (CTC_CMD_VARARG(str))
                    {
                        if (match_type < CTC_VARARG_MATCH)
                        {
                            match_type = CTC_VARARG_MATCH;
                        }

                        matched++;
                    }
                    else if (CTC_CMD_RANGE(str))
                    {
                        if (ctc_cmd_CTC_RANGE_MATCH(str, command))
                        {
                            if (match_type < CTC_RANGE_MATCH)
                            {
                                match_type = CTC_RANGE_MATCH;
                            }

                            matched++;
                        }
                    }
                    else if (CTC_CMD_IPV6(str))
                    {
                        if (ctc_cmd_CTC_IPV6_MATCH(command) == CTC_EXACT_MATCH)
                        {
                            if (match_type < CTC_IPV6_MATCH)
                            {
                                match_type = CTC_IPV6_MATCH;
                            }

                            matched++;
                        }
                    }
                    else if (CTC_CMD_IPV6_PREFIX(str))
                    {
                        if (ctc_cmd_CTC_IPV6_PREFIX_MATCH(command) == CTC_EXACT_MATCH)
                        {
                            if (match_type < CTC_IPV6_PREFIX_MATCH)
                            {
                                match_type = CTC_IPV6_PREFIX_MATCH;
                            }

                            matched++;
                        }
                    }
                    else if (CTC_CMD_IPV4(str))
                    {
                        if (ctc_cmd_CTC_IPV4_MATCH(command) == CTC_EXACT_MATCH)
                        {
                            if (match_type < CTC_IPV4_MATCH)
                            {
                                match_type = CTC_IPV4_MATCH;
                            }

                            matched++;
                        }
                    }
                    else if (CTC_CMD_IPV4_PREFIX(str))
                    {
                        if (ctc_cmd_CTC_IPV4_PREFIX_MATCH(command) == CTC_EXACT_MATCH)
                        {
                            if (match_type < CTC_IPV4_PREFIX_MATCH)
                            {
                                match_type = CTC_IPV4_PREFIX_MATCH;
                            }

                            matched++;
                        }
                    }
                    else if (CTC_CMD_OPTION(str) || CTC_CMD_VARIABLE(str))
                    {
                        if (match_type < CTC_EXTEND_MATCH)
                        {
                            match_type = CTC_EXTEND_MATCH;
                        }

                        matched++;
                    }
                    else
                    {
                        if (sal_strcmp(command, str) == 0)
                        {
                            match_type = CTC_EXACT_MATCH;
                            matched++;
                        }
                    }
                }

                if (!matched)
                {
                    vector_slot(v, i) = NULL;
                }
            }
        }
    }

    return match_type;
}

/* Check ambiguous match */
int32
is_cmd_ambiguous(char* command, vector v, int32 index, ctc_match_type_t type)
{
    int32 i;
    int32 j;
    char* str = NULL;
    ctc_cmd_element_t* cmd_element;
    char* matched = NULL;
    vector descvec;
    ctc_cmd_desc_t* desc;

    for (i = 0; i < vector_max(v); i++)
    {
        if ((cmd_element = vector_slot(v, i)) != NULL)
        {
            int32 match = 0;
            descvec = vector_slot(cmd_element->strvec, index);

            for (j = 0; j < vector_max(descvec); j++)
            {
                ctc_match_type_t ret;

                desc = vector_slot(descvec, j);
                str = desc->cmd;
                if (!str)
                {
                    continue;
                }

                switch (type)
                {
                case CTC_EXACT_MATCH:
                    if (!(CTC_CMD_OPTION(str) || CTC_CMD_VARIABLE(str))
                        && sal_strcmp(command, str) == 0)
                    {
                        match++;
                    }

                    break;

                case CTC_PARTLY_MATCH:
                    if (!(CTC_CMD_OPTION(str) || CTC_CMD_VARIABLE(str))
                        && sal_strncmp(command, str, sal_strlen(command)) == 0)
                    {
                        if (matched && sal_strcmp(matched, str) != 0)
                        {
                            return 1; /* There is ambiguous match. */
                        }
                        else
                        {
                            matched = str;
                        }

                        match++;
                    }

                    break;

                case CTC_RANGE_MATCH:
                    if (ctc_cmd_CTC_RANGE_MATCH(str, command))
                    {
                        if (matched && sal_strcmp(matched, str) != 0)
                        {
                            return 1;
                        }
                        else
                        {
                            matched = str;
                        }

                        match++;
                    }

                    break;

                case CTC_IPV6_MATCH:
                    if (CTC_CMD_IPV6(str))
                    {
                        match++;
                    }

                    break;

                case CTC_IPV6_PREFIX_MATCH:
                    if ((ret = ctc_cmd_CTC_IPV6_PREFIX_MATCH(command)) != CTC_CTC_NO_MATCH)
                    {
                        if (ret == CTC_PARTLY_MATCH)
                        {
                            return 2; /* There is incomplete match. */

                        }

                        match++;
                    }

                    break;

                case CTC_IPV4_MATCH:
                    if (CTC_CMD_IPV4(str))
                    {
                        match++;
                    }

                    break;

                case CTC_IPV4_PREFIX_MATCH:
                    if ((ret = ctc_cmd_CTC_IPV4_PREFIX_MATCH(command)) != CTC_CTC_NO_MATCH)
                    {
                        if (ret == CTC_PARTLY_MATCH)
                        {
                            return 2; /* There is incomplete match. */

                        }

                        match++;
                    }

                    break;

                case CTC_EXTEND_MATCH:
                    if (CTC_CMD_OPTION(str) || CTC_CMD_VARIABLE(str))
                    {
                        match++;
                    }

                    break;

                case CTC_OPTION_MATCH:
                    match++;
                    break;

                case CTC_CTC_NO_MATCH:
                default:
                    break;
                }
            } /* for */

            if (!match)
            {
                vector_slot(v, i) = NULL;
                if (cmd_debug)
                {
                    ctc_cli_out("vector %d filtered by is_cmd_ambiguous\n\r", i);
                }
            }
        }
    }

    return 0;
}

/* If src matches dst return dst string, otherwise return NULL */
char*
ctc_cmd_entry_function(char* src, char* dst)
{
    /* Skip variable arguments. */
    if (CTC_CMD_OPTION(dst) || CTC_CMD_VARIABLE(dst) || CTC_CMD_VARARG(dst) ||
        CTC_CMD_IPV4(dst) || CTC_CMD_IPV4_PREFIX(dst) || CTC_CMD_RANGE(dst))
    {
        return NULL;
    }

    /* In case of 'command \t', given src is NULL string. */
    if (src == NULL)
    {
        return dst;
    }

    /* Matched with input string. */
    if (sal_strncmp(src, dst, sal_strlen(src)) == 0)
    {
        return dst;
    }

    return NULL;
}

/* If src matches dst return dst string, otherwise return NULL */
/* This version will return the dst string always if it is
   CTC_CMD_VARIABLE for '?' key processing */
char*
ctc_cmd_entry_function_desc(char* src, char* dst)
{
    if (CTC_CMD_VARARG(dst))
    {
        return dst;
    }

    if (CTC_CMD_RANGE(dst))
    {
        if (ctc_cmd_CTC_RANGE_MATCH(dst, src))
        {
            return dst;
        }
        else
        {
            return NULL;
        }
    }

    if (CTC_CMD_IPV6(dst))
    {
        if (ctc_cmd_CTC_IPV6_MATCH(src))
        {
            return dst;
        }
        else
        {
            return NULL;
        }
    }

    if (CTC_CMD_IPV6_PREFIX(dst))
    {
        if (ctc_cmd_CTC_IPV6_PREFIX_MATCH(src))
        {
            return dst;
        }
        else
        {
            return NULL;
        }
    }

    if (CTC_CMD_IPV4(dst))
    {
        if (ctc_cmd_CTC_IPV4_MATCH(src))
        {
            return dst;
        }
        else
        {
            return NULL;
        }
    }

    if (CTC_CMD_IPV4_PREFIX(dst))
    {
        if (ctc_cmd_CTC_IPV4_PREFIX_MATCH(src))
        {
            return dst;
        }
        else
        {
            return NULL;
        }
    }

    /* Optional or variable commands always match on '?' */
    if (CTC_CMD_OPTION(dst) || CTC_CMD_VARIABLE(dst))
    {
        return dst;
    }

    /* In case of 'command \t', given src is NULL string. */
    if (src == NULL)
    {
        return dst;
    }

    if (sal_strncmp(src, dst, sal_strlen(src)) == 0)
    {
        return dst;
    }
    else
    {
        return NULL;
    }
}

/* Check same string element existence.  If it isn't there return
    1. */
int32
ctc_cmd_unique_string(vector v, char* str)
{
    int32 i;
    char* match;

    for (i = 0; i < vector_max(v); i++)
    {
        if ((match = vector_slot(v, i)) != NULL)
        {
            if (sal_strcmp(match, str) == 0)
            {
                return 0;
            }
        }
    }

    return 1;
}

/* Compare string to description vector.  If there is same string
   return 1 else return 0. */
int32
desc_unique_string(vector v, char* str)
{
    int32 i;
    ctc_cmd_desc_t* desc;

    for (i = 0; i < vector_max(v); i++)
    {
        if ((desc = vector_slot(v, i)) != NULL)
        {
            if (sal_strcmp(desc->cmd, str) == 0)
            {
                return 1;
            }
        }
    }

    return 0;
}

#define INIT_MATCHVEC_SIZE 10
#define VECTOR_SET \
    if (if_describe) \
    { \
        if (!desc_unique_string(matchvec, string)) \
        { \
            ctc_vti_vec_set(matchvec, desc); \
        } \
    } \
    else \
    { \
        if (ctc_cmd_unique_string(matchvec, string)) \
        { \
            ctc_vti_vec_set(matchvec, XSTRDUP(MTYPE_TMP, string)); \
        } \
    }

ctc_match_type_t
ctc_cmd_string_match(char* str, char* command)
{
    ctc_match_type_t match_type = CTC_CTC_NO_MATCH;

    if (CTC_CMD_VARARG(str))
    {
        match_type = CTC_VARARG_MATCH;
    }
    else if (CTC_CMD_RANGE(str))
    {
        if (ctc_cmd_CTC_RANGE_MATCH(str, command))
        {
            match_type = CTC_RANGE_MATCH;
        }
    }
    else if (CTC_CMD_IPV6(str))
    {
        if (ctc_cmd_CTC_IPV6_MATCH(command))
        {
            match_type = CTC_IPV6_MATCH;
        }
    }
    else if (CTC_CMD_IPV6_PREFIX(str))
    {
        if (ctc_cmd_CTC_IPV6_PREFIX_MATCH(command))
        {
            match_type = CTC_IPV6_PREFIX_MATCH;
        }
    }
    else if (CTC_CMD_IPV4(str))
    {
        if (ctc_cmd_CTC_IPV4_MATCH(command))
        {
            match_type = CTC_IPV4_MATCH;
        }
    }
    else if (CTC_CMD_IPV4_PREFIX(str))
    {
        if (ctc_cmd_CTC_IPV4_PREFIX_MATCH(command))
        {
            match_type = CTC_IPV4_PREFIX_MATCH;
        }
    }
    else if (CTC_CMD_OPTION(str) || CTC_CMD_VARIABLE(str))
    {
        match_type = CTC_EXTEND_MATCH;
    }
    else if (sal_strncmp(command, str, sal_strlen(command)) == 0)
    {
        if (sal_strcmp(command, str) == 0)
        {
            match_type = CTC_EXACT_MATCH;
        }
        else
        {
            match_type = CTC_PARTLY_MATCH;
        }
    }

    return match_type;
}

ctc_match_type_t
ctc_cmd_filter_command_tree(vector str_vec, vector vline, int32* index, ctc_cmd_desc_t** matched_desc_ptr, int32 depth, int32* if_CTC_EXACT_MATCH)
{
    int32 j = 0;
    char* str = NULL;
    ctc_match_type_t match_type = CTC_CTC_NO_MATCH;
    vector cur_vec = NULL;
    ctc_cmd_desc_t* desc = NULL;
    char* command = NULL;
    int32 old_index = 0;
    int32 k = 0;
    int32 no_option = 0;

    while (*index < vector_max(vline))
    {
        command = vector_slot(vline, *index);
        if (!command)
        {
            return CTC_OPTION_MATCH;
        }

        if (str_vec->is_desc)
        {
            if (str_vec->direction == 0) /* Tranverse */
            {
                for (j = 0; j < vector_max(str_vec); j++)
                {
                    desc = vector_slot(str_vec, j);
                    str = desc->cmd;
                    if ((match_type = ctc_cmd_string_match(str, command)) == CTC_CTC_NO_MATCH)
                    {
                        return CTC_CTC_NO_MATCH;
                    }
                    else /* matched */
                    {
                        matched_desc_ptr[*index] = desc;
                        (*index)++;
                        if (*index < vector_max(vline))
                        {
                            command = vector_slot(vline, *index);
                            if (!command) /* next is null */
                            {
                                return CTC_OPTION_MATCH;
                            }
                        }
                        else
                        {
                            j++;
                            break;
                        }
                    }
                }

                if (j < vector_max(str_vec))
                {
                    return CTC_INCOMPLETE_CMD;
                }

                return match_type;
            }
            else /* vertical */
            {
                for (j = 0; j < vector_max(str_vec); j++)
                {
                    desc = vector_slot(str_vec, j);
                    str = desc->cmd;
                    if ((match_type = ctc_cmd_string_match(str, command)) == CTC_CTC_NO_MATCH)
                    {
                        continue;
                    }
                    else
                    {
                        matched_desc_ptr[*index] = desc;
                        (*index)++;
                        break;
                    }
                }

                if (match_type == CTC_CTC_NO_MATCH)
                {
                    if (vector_max(str_vec) > 1)
                    {
                        return CTC_CTC_NO_MATCH;
                    }
                    else /* if vetical vector and only has one element, it is optional */
                    {
                        return CTC_OPTION_MATCH;
                    }
                }
                else
                {
                    return match_type;
                }
            }
        }
        else /* shall go to next level's vector */
        {
            if (str_vec->direction == 0) /* Tranverse */
            {
                for (j = 0; j < vector_max(str_vec); j++)
                {
                    cur_vec = vector_slot(str_vec, j);
                    if (cur_vec->direction && vector_max(cur_vec) == 1) /* optinal vector */
                    {
                        while (!cur_vec->is_desc)
                        {
                            cur_vec = vector_slot(cur_vec, 0);
                        }

                        desc = vector_slot(cur_vec, 0);
                        command = vector_slot(vline, *index);
                        if (command && CTC_CMD_VARIABLE(desc->cmd) && !CTC_CMD_NUMBER(command) && !CTC_CMD_VARIABLE(command)) /* skip if input is keyword but desc is VAR */
                        {
                            if (cmd_debug)
                            {
                                ctc_cli_out("\n\rLine: %d, index=%d,  skip if input is keyword but desc is VAR", __LINE__, *index);
                            }

                            continue;
                        }
                    }

                    cur_vec = vector_slot(str_vec, j); /* retry to get the current vector */
                    if ((match_type = ctc_cmd_filter_command_tree(cur_vec, vline, index, matched_desc_ptr, depth + 1, if_CTC_EXACT_MATCH)) == CTC_CTC_NO_MATCH)
                    {
                        return CTC_CTC_NO_MATCH;
                    } /* else, matched, index will be increased and go on next match */

                    /* else, matched, index will be increased and go on next match */
                    if (*index >= vector_max(vline))
                    {
                        j++;
                        if (cmd_debug)
                        {
                            ctc_cli_out("\n\rLine: %d, index=%d, j=%d: reach the end of input word", __LINE__, *index, j);
                        }

                        break;
                    }
                }

                no_option = 0;

                for (k = j; k < vector_max(str_vec); k++) /* check if all the left cmds in the tranverse list can be skipped */
                {
                    cur_vec = vector_slot(str_vec, k);
                    #if 0
                    if (!cur_vec->direction || vector_max(cur_vec) > 1) /* optional vector shall be vertical and has one cmd*/
                    {
                        no_option = 1;
                        break;
                    }
                    #endif
                    if (!cur_vec->is_option)
                    {
                        no_option = 1;
                        break;
                    }
                }

                if ((j < vector_max(str_vec)) && no_option)
                {
                    return CTC_INCOMPLETE_CMD;
                }

                /* too many input words */
                if (depth == 0 && *index != vector_max(vline) && (command = vector_slot(vline, *index)))
                {
                    if (cmd_debug)
                    {
                        ctc_cli_out("\n\rLine: %d, index=%d,  too more cmds", __LINE__, *index);
                    }

                    return CTC_CTC_NO_MATCH;
                }

                return match_type;
            }
            else /* Vertical */
            {
                int32 cbrace_matched = 0;
                int32 cbrace_try_result = 0;
                if (str_vec->is_multiple)
                {
                    char match_j[MAX_OPTIONAL_CMD_NUM] = {0};
                    if (cmd_debug)
                    {
                        ctc_cli_out("\r\nLine %d: *index: %d, entering cbrace checking", __LINE__, *index);
                    }

                    do
                    {
                        cbrace_try_result = 0;

                        for (j = 0; j < vector_max(str_vec); j++)
                        {
                            if (j >= MAX_OPTIONAL_CMD_NUM)
                            {
                                ctc_cli_out("\n\rLine: %d, index=%d,  too many optional cmds", __LINE__, *index);
                                break;
                            }

                            if (!match_j[j])
                            {
                                cur_vec = vector_slot(str_vec, j);
                                match_type = ctc_cmd_filter_command_tree(cur_vec, vline, index, matched_desc_ptr, depth + 1, if_CTC_EXACT_MATCH);
                                if (match_type == CTC_CTC_NO_MATCH)
                                {
                                    continue;
                                }
                                else if (match_type == CTC_INCOMPLETE_CMD)
                                {
                                    return CTC_INCOMPLETE_CMD;
                                }
                                else
                                {
                                    match_j[j] = 1;
                                    cbrace_matched++;
                                    cbrace_try_result++;
                                    break;
                                }
                            }
                        }
                    }
                    while (cbrace_try_result); /* if match none, shall exit loop */

                    if (cbrace_matched)
                    {
                        if (cmd_debug)
                        {
                            ctc_cli_out("\r\ncbrace_matched: Line %d: *index: %d, command: %s, j: %d", __LINE__, *index, command, j);
                        }

                        return CTC_OPTION_MATCH;
                    }
                    else
                    {
                        if (cmd_debug)
                        {
                            ctc_cli_out("\r\nNone cbrace matched in Line %d: *index: %d, command: %s, j: %d", __LINE__, *index, command, j);
                        }
                    }
                }
                else /* paren:(a1 |a2 ) */
                {
                    int32 matched_j = -1;
                    ctc_match_type_t previous_match_type = CTC_CTC_NO_MATCH;
                    old_index = *index;

                    for (j = 0; j < vector_max(str_vec); j++) /* try to get best match in the paren list */
                    {
                        cur_vec = vector_slot(str_vec, j);
                        *index = old_index;
                        if (!cur_vec->is_desc)
                        {
                            match_type = ctc_cmd_filter_command_tree(cur_vec, vline, index, matched_desc_ptr, depth + 1, if_CTC_EXACT_MATCH);
                        }
                        else
                        {
                            desc = vector_slot(cur_vec, 0);
                            str = desc->cmd;
                            command = vector_slot(vline, *index);
                            match_type = ctc_cmd_string_match(str, command);
                        }

                        if (match_type > previous_match_type)
                        {
                            previous_match_type = match_type;
                            matched_j = j;
                        }
                    }

                    if (previous_match_type != CTC_CTC_NO_MATCH) /* found best match */
                    {
                        cur_vec = vector_slot(str_vec, matched_j);
                        *index = old_index;
                        match_type = ctc_cmd_filter_command_tree(cur_vec, vline, index, matched_desc_ptr, depth + 1, if_CTC_EXACT_MATCH);
                        if (cmd_debug)
                        {
                            ctc_cli_out("\r\nLine %d: *index: %d, Found best match %d, returned type: %d",  __LINE__, *index, matched_j, match_type);
                        }

                        return match_type;
                    }
                    else /* no match */
                    {
                        if (vector_max(str_vec) > 1)
                        {
                            return CTC_CTC_NO_MATCH;
                        }
                        else  /* if vertical vector only has one element, it is optional */
                        {
                            return CTC_OPTION_MATCH;
                        }
                    }
                }

                return match_type;
            }
        }
    } /* while */

    return match_type;
}

ctc_match_type_t
ctc_cmd_filter_by_completion(vector strvec, vector vline, ctc_cmd_desc_t** matched_desc_ptr, int32* if_CTC_EXACT_MATCH)
{
    int32 index = 0;

    return ctc_cmd_filter_command_tree(strvec, vline, &index, matched_desc_ptr, 0, if_CTC_EXACT_MATCH);
}

static ctc_cmd_desc_t desc_cr = { "<cr>", "" };
/*returns: 0 no match; 1 matched but not last word, continue searching; 2 match and last word, finish searching */
int32
ctc_cmd_describe_cmd_tree(vector vline, int32* index, vector str_vec, vector matchvec, int32 if_describe, int32 depth)
{
    int32 j = 0;
    int32 ret = 0;
    char* str = NULL;
    ctc_match_type_t match_type = CTC_CTC_NO_MATCH;
    vector cur_vec = NULL;
    ctc_cmd_desc_t* desc = NULL;
    char* command = NULL;
    char* string = NULL;
    int32 old_index  = 0;

    while (*index < vector_max(vline))
    {
        command = vector_slot(vline, *index);

        if (str_vec->is_desc)
        {
            if (str_vec->direction == 0) /* Tranverse */
            {
                int32 if_CTC_EXACT_MATCH = 0;

                for (j = 0; j < vector_max(str_vec); j++)
                {
                    command = vector_slot(vline, *index);
                    desc = vector_slot(str_vec, j);
                    str = desc->cmd;

                    if (command) /* not null command */
                    {
                        if ((match_type = ctc_cmd_string_match(str, command)) == CTC_CTC_NO_MATCH)
                        {
                            return 0;
                        }
                        else /* matched */
                        {
                            if (*index == (vector_max(vline) - 1)) /* command is last string*/
                            {
                                string = ctc_cmd_entry_function_desc(command, desc->cmd);
                                if (string)
                                {
                                    VECTOR_SET;
                                }

                                if (cmd_debug)
                                {
                                    ctc_cli_out("\r\nLine %d:depth: %d, *index: %d, string: %s, j: %d", __LINE__, depth, *index, string, j);
                                }

                                return 2; /* not null, last word match */
                            }
                            else /* not null, not last word */
                            {
                                (*index)++;
                                command = vector_slot(vline, *index);
                                if (cmd_debug)
                                {
                                    ctc_cli_out("\r\nLine %d:depth: %d, *index: %d, command: %s, j: %d", __LINE__, depth, *index, command, j);
                                }

                                if (CTC_PARTLY_MATCH != match_type)
                                {
                                    if_CTC_EXACT_MATCH = 1; /* exact match */
                                }
                            }
                        }
                    }
                    else /* command is null, always the last word */
                    {
                        string = ctc_cmd_entry_function_desc(command, desc->cmd);
                        if (string)
                        {
                            VECTOR_SET;
                        }

                        if (cmd_debug)
                        {
                            ctc_cli_out("\r\nLine %d:depth: %d, *index: %d, string: %s, j: %d", __LINE__, depth, *index, string, j);
                        }

                        return 2;
                    }
                }

                if (cmd_debug)
                {
                    ctc_cli_out("\r\nLine %d:depth: %d, *index: %d, command: %s, j: %d", __LINE__, depth, *index, command, j);
                }

                return 1;
            }
            else /* vertical */
            {
                command = vector_slot(vline, *index);
                if (command) /* not null */
                {
                    if (*index == (vector_max(vline) - 1)) /* command is last string */
                    {
                        for (j = 0; j < vector_max(str_vec); j++)
                        {
                            desc = vector_slot(str_vec, j);
                            str = desc->cmd;
                            if ((match_type = ctc_cmd_string_match(str, command)) != CTC_CTC_NO_MATCH)
                            {
                                string = ctc_cmd_entry_function_desc(command, desc->cmd);
                                if (string)
                                {
                                    VECTOR_SET;
                                }

                                if (cmd_debug)
                                {
                                    ctc_cli_out("\r\nLine %d:depth: %d, *index: %d, command: %s, j: %d", __LINE__, depth, *index, command, j);
                                }

                                return 2; /* shall match only one */
                            }
                        } /* for j */

                    }
                    else /* command not last word */
                    {
                        for (j = 0; j < vector_max(str_vec); j++)
                        {
                            desc = vector_slot(str_vec, j);
                            str = desc->cmd;
                            if ((match_type = ctc_cmd_string_match(str, command)) != CTC_CTC_NO_MATCH)
                            {
                                if (cmd_debug)
                                {
                                    ctc_cli_out("\r\nLine %d:depth: %d, *index: %d, command: %s, j: %d", __LINE__, depth, *index, command, j);
                                }

                                return 1; /* shall match only one */
                            }
                        } /* for j */

                    }
                }
                else /*  last string, null command */
                {
                    for (j = 0; j < vector_max(str_vec); j++)
                    {
                        desc = vector_slot(str_vec, j);
                        str = desc->cmd;
                        string = ctc_cmd_entry_function_desc(command, desc->cmd);
                        if (string)
                        {
                            VECTOR_SET;
                        }
                    } /* for j */

                    if (cmd_debug)
                    {
                        ctc_cli_out("\r\nLine %d:depth: %d, *index: %d, command: %s, j: %d", __LINE__, depth, *index, command, j);
                    }

                    return 2;
                }

                if (cmd_debug)
                {
                    ctc_cli_out("\r\nLine %d:depth: %d, *index: %d, command: %s, j: %d", __LINE__, depth, *index, command, j);
                }

                return 0;
            }
        }
        else /* shall go to next level's vector */
        {
            if (str_vec->direction == 0) /* Tranverse */
            {
                for (j = 0; j < vector_max(str_vec); j++)
                {
                    cur_vec = vector_slot(str_vec, j);
                    if (cur_vec->direction && vector_max(cur_vec) == 1) /* optinal vector */
                    {
                        while (!cur_vec->is_desc)
                        {
                            cur_vec = vector_slot(cur_vec, 0);
                        }

                        desc = vector_slot(cur_vec, 0);
                        command = vector_slot(vline, *index);
                        if (command && CTC_CMD_VARIABLE(desc->cmd) && !CTC_CMD_NUMBER(command) && !CTC_CMD_VARIABLE(command)) /* skip if input is keyword but desc is VAR */
                        {
                            continue;
                        }
                    }

                    cur_vec = vector_slot(str_vec, j); /* retry to get the current vector */
                    old_index = *index;
                    ret = ctc_cmd_describe_cmd_tree(vline, index, cur_vec, matchvec, if_describe, depth + 1);
                    if (ret == 2)
                    {
                        if (cur_vec->direction && vector_max(cur_vec) == 1 && (old_index == *index)) /* optional vector */
                        { /*(old_index == *index) means index is not increased in the optional vector */
                            continue;
                        }

                        if (cmd_debug)
                        {
                            ctc_cli_out("\r\nLine %d:depth: %d, *index: %d, command: %s, j: %d", __LINE__, depth, *index, command, j);
                        }

                        return 2;
                    }

                    if (ret == 3)
                    {
                        return 3;
                    }

                    if (ret == 0)
                    {
                        if (cmd_debug)
                        {
                            ctc_cli_out("\r\nLine %d:depth: %d, *index: %d, command: %s, j: %d ", __LINE__, depth, *index, command, j);
                        }

                        return 0;
                    }
                }

                if (!depth && (j == vector_max(str_vec)) && ((command = vector_slot(vline, *index)) == NULL)) /* all tranverse vector has been searched */
                {
                    if (cmd_debug)
                    {
                        ctc_cli_out("\r\nLine %d:depth: %d, *index: %d, command: %s, j: %d ", __LINE__, depth, *index, command, j);
                    }

                    string = "<cr>";

                    if (if_describe)
                    {
                        if (!desc_unique_string(matchvec, string))
                        {
                            ctc_vti_vec_set(matchvec, &desc_cr);
                        }
                    }
                    else
                    {
                        if (ctc_cmd_unique_string(matchvec, string))
                        {
                            ctc_vti_vec_set(matchvec, XSTRDUP(MTYPE_TMP, desc_cr.cmd));
                        }
                    }
                }

                if (cmd_debug)
                {
                    ctc_cli_out("\r\nLine %d:depth: %d, *index: %d, command: %s, j: %d", __LINE__, depth, *index, command, j);
                }

                return 1;
            }
            else /* Vertical */
            {
                if (str_vec->is_multiple) /* {a1|a2} */
                {
                    char match_j[100] = {0};
                    int32  cbrace_try_result = 0;
                    int32 cbrace_matched = 0;

                    do
                    {
                        cbrace_try_result = 0;

                        for (j = 0; j < vector_max(str_vec); j++)
                        {
                            cur_vec = vector_slot(str_vec, j);
                            command = vector_slot(vline, *index);
                            if (!command) /* it's time to match NULL */
                            {
                                break;
                            }

                            if (!match_j[j]) /* find those not searched */
                            {
                                if (*index == (vector_max(vline) - 1)) /* last word */
                                {
                                    ret = ctc_cmd_describe_cmd_tree(vline, index, cur_vec, matchvec, if_describe, depth + 1);
                                    if (ret)
                                    {
                                        if (cmd_debug)
                                        {
                                            ctc_cli_out("\r\nLine %d:depth: %d, *index: %d, command: %s, j: %d, ret: %d", __LINE__, depth, *index, command, j, ret);
                                        }

                                        return ret;
                                    }
                                }
                                else /* not last word */
                                {
                                    old_index = *index;
                                    ret = ctc_cmd_describe_cmd_tree(vline, index, cur_vec, matchvec, if_describe, depth + 1);
                                    if (ret)
                                    {
                                        match_j[j] = 1; /* matched */
                                        cbrace_matched++;
                                        cbrace_try_result++;
                                        command = vector_slot(vline, *index);
                                        if ((!command || vector_max(cur_vec) > 1) && (ret == 2)) /* "a1 A1" format in one of the list */
                                        {
                                            return 3;
                                        }
                                    }
                                    else
                                    {
                                        if (*index > old_index) /* inner "a1 A1" format but no match */
                                        {
                                            return 0;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    while (cbrace_try_result);  /* if match none, shall exit loop */

                    if (!command)
                    {
                        for (j = 0; j < vector_max(str_vec); j++)
                        {
                            cur_vec = vector_slot(str_vec, j);
                            if (!match_j[j])
                            {
                                ret = ctc_cmd_describe_cmd_tree(vline, index, cur_vec, matchvec, if_describe, depth + 1);
                            }
                        }
                    }

                    if (cmd_debug)
                    {
                        ctc_cli_out("\r\nLine %d:depth: %d, *index: %d, command: %s, j: %d, ret: %d", __LINE__, depth, *index, command, j, ret);
                    }

                    if (cbrace_matched)
                    {
                        return 1;
                    }
                    else
                    {
                        return ret;
                    }
                } /* end of {} */
                else /*(a1|a2) */
                {
                    if (*index != (vector_max(vline) - 1)) /* not last word */
                    {
                        int32 matched_j = -1;
                        ctc_match_type_t previous_match_type = CTC_CTC_NO_MATCH;
                        old_index = *index;

                        for (j = 0; j < vector_max(str_vec); j++)
                        {
                            *index = old_index;
                            cur_vec = vector_slot(str_vec, j);
                            if (!cur_vec->is_desc)
                            {
                                match_type = ctc_cmd_describe_cmd_tree(vline, index, cur_vec, matchvec, if_describe, depth + 1);
                            }
                            else
                            {
                                desc = vector_slot(cur_vec, 0);
                                str = desc->cmd;
                                command = vector_slot(vline, *index);
                                match_type = ctc_cmd_string_match(str, command);
                            }

                            if (match_type > previous_match_type)
                            {
                                previous_match_type = match_type;
                                matched_j = j;
                            }
                        }

                        if (previous_match_type != CTC_CTC_NO_MATCH) /* found best match*/
                        {
                            cur_vec = vector_slot(str_vec, matched_j);
                            *index = old_index;
                            ret = ctc_cmd_describe_cmd_tree(vline, index, cur_vec, matchvec, if_describe, depth + 1);
                        }
                        else /* all list not matched*/
                        {
                            ret = 0;
                        }
                    }
                    else /*last word, can be null */
                    {
                        int32 if_matched = 0;

                        for (j = 0; j < vector_max(str_vec); j++)
                        {
                            cur_vec = vector_slot(str_vec, j);
                            ret = ctc_cmd_describe_cmd_tree(vline, index, cur_vec, matchvec, if_describe, depth + 1);
                            if (ret)
                            {
                                if_matched = ret;
                            }
                        }

                        ret = if_matched;
                    }

                    if (ret == 0 && vector_max(str_vec) == 1) /* optional vector, can skill matching NULL command */
                    {
                        return 1;
                    }

                    if (cmd_debug)
                    {
                        ctc_cli_out("\r\nLine %d:depth: %d, *index: %d, command: %s, j: %d, ret: %d", __LINE__, depth, *index, command, j, ret);
                    }

                    return ret;
                }
            }
        }
    } /* while */

    if (cmd_debug)
    {
        ctc_cli_out("\r\nLine %d:depth: %d, *index: %d, command: %s, j: %d \n\r", __LINE__, depth, *index, command, j);
    }

    return ret;
}

vector
ctc_cmd_describe_complete_cmd(vector vline, vector cmd_vector, vector matchvec, int32 if_describe)
{
    int32 i = 0;
    int32 index = 0;
    ctc_cmd_element_t* cmd_element = NULL;

    for (i = 0; i < vector_max(cmd_vector); i++)
    {
        index = 0;
        if ((cmd_element = vector_slot(cmd_vector, i)) != NULL)
        {
            ctc_cmd_describe_cmd_tree(vline, &index, cmd_element->strvec, matchvec, if_describe, 0);
        }
    }

    return matchvec;
}

/* '?' describe command support. */
vector
ctc_cmd_describe_command(vector vline, ctc_vti_t* vti, int32* status)
{
    int32 i;
    int32 if_CTC_EXACT_MATCH = 0;

    vector cmd_vector;
    vector matchvec;
    ctc_match_type_t match;
    ctc_cmd_element_t* cmd_element = NULL;

    int32 best_match_type = 0;
    unsigned short matched_count[3] = {0};
    char* CTC_PARTLY_MATCH_element = NULL;
    char* CTC_EXTEND_MATCH_element = NULL;

    /* Make copy vector of current node's command vector. */
    cmd_vector = ctc_vti_vec_copy(ctc_cmd_node_vector(cmdvec, vti->node));
    if (!cmd_vector)
    {
        *status = CMD_SYS_ERROR;
        return NULL;
    }

    /* Prepare match vector */
    matchvec = ctc_vti_vec_init(INIT_MATCHVEC_SIZE);

    CTC_PARTLY_MATCH_element = (char*)sal_alloc(sizeof(char) * MAX_ELEMENT_NUM, "clicmd");
    CTC_EXTEND_MATCH_element = (char*)sal_alloc(sizeof(char) * MAX_ELEMENT_NUM, "clicmd");

    if (!CTC_PARTLY_MATCH_element || !CTC_EXTEND_MATCH_element)
    {
        ctc_cli_out("\n\rError: no memory!!");
    }

    sal_memset(CTC_PARTLY_MATCH_element, 0, sizeof(char) * MAX_ELEMENT_NUM);
    sal_memset(CTC_EXTEND_MATCH_element, 0, sizeof(char) * MAX_ELEMENT_NUM);

    /* filter command elements */
    if (vector_slot(vline, 0) != NULL)
    {
        for (i = 0; i < vector_max(cmd_vector); i++)
        {
            match = 0;
            if_CTC_EXACT_MATCH = 1;
            cmd_element = vector_slot(cmd_vector, i);
            if (cmd_element)
            {
                match = ctc_cmd_filter_by_completion(cmd_element->strvec, vline, matched_desc_ptr, &if_CTC_EXACT_MATCH);
                if (!match)
                {
                    vector_slot(cmd_vector, i) = NULL;
                    /*
                    if(cmd_debug)
                    {
                        ctc_cli_out("cmd element %d filtered \n\r", i);
                    }*/
                }
                else /* matched, save the exact match element*/
                {
                    best_match_type = ctc_cmd_best_match_check(vline, matched_desc_ptr, 1);
                    matched_count[best_match_type]++;
                    if (best_match_type == CTC_CMD_PARTLY_MATCH)
                    {
                        CTC_PARTLY_MATCH_element[i] = 1;
                        CTC_EXTEND_MATCH_element[i] = 0;
                    }
                    else if (best_match_type == CTC_CMD_EXTEND_MATCH)
                    {
                        CTC_EXTEND_MATCH_element[i] = 1;
                        CTC_PARTLY_MATCH_element[i] = 0;
                    }
                    else
                    {
                        CTC_EXTEND_MATCH_element[i] = 0;
                        CTC_PARTLY_MATCH_element[i] = 0;
                    }

                    if (cmd_debug)
                    {
                        ctc_cli_out("cmd element %d best matched %d: %s \n\r", i, best_match_type, cmd_element->string);
                    }
                }
            }
        } /* for cmd filtering */

    }

    if (matched_count[CTC_CMD_EXACT_MATCH]) /* found exact match, filter all partly and extend match elements */
    {
        for (i = 0; i < vector_max(cmd_vector); i++)
        {
            if (CTC_EXTEND_MATCH_element[i] || CTC_PARTLY_MATCH_element[i]) /* filter all other elements */
            {
                vector_slot(cmd_vector, i) = NULL;
                if (cmd_debug)
                {
                    ctc_cli_out("cmd element %d filterd for not exact match \n\r", i);
                }
            }
        }
    }
    else if (matched_count[CTC_CMD_PARTLY_MATCH]) /* found partly match, filter all extend match elements */
    {
        for (i = 0; i < vector_max(cmd_vector); i++)
        {
            if (CTC_EXTEND_MATCH_element[i]) /* filter all other elements */
            {
                vector_slot(cmd_vector, i) = NULL;
                if (cmd_debug)
                {
                    ctc_cli_out("cmd element %d filterd for not exact match \n\r", i);
                }
            }
        }
    }

    sal_free(CTC_PARTLY_MATCH_element);
    sal_free(CTC_EXTEND_MATCH_element);

    /* make desc vector */
    matchvec = ctc_cmd_describe_complete_cmd(vline, cmd_vector, matchvec, 1);

    ctc_vti_vec_free(cmd_vector);

    if (vector_slot(matchvec, 0) == NULL)
    {
        ctc_vti_vec_free(matchvec);
        *status = CMD_ERR_NO_MATCH;
    }
    else
    {
        *status = CMD_SUCCESS;
    }

    return matchvec;
}

/* Check LCD of matched command. */
int32
ctc_cmd_lcd(char** matched)
{
    int32 i;
    int32 j;
    int32 lcd = -1;
    char* s1, * s2;
    char c1, c2;

    if (matched[0] == NULL || matched[1] == NULL)
    {
        return 0;
    }

    for (i = 1; matched[i] != NULL; i++)
    {
        s1 = matched[i - 1];
        s2 = matched[i];

        for (j = 0; (c1 = s1[j]) && (c2 = s2[j]); j++)
        {
            if (c1 != c2)
            {
                break;
            }
        }

        if (lcd < 0)
        {
            lcd = j;
        }
        else
        {
            if (lcd > j)
            {
                lcd = j;
            }
        }
    }

    return lcd;
}

/* Command line completion support. */
char**
ctc_cmd_complete_command(vector vline, ctc_vti_t* vti, int32* status)
{
    int32 i = 0;
    int32 if_CTC_EXACT_MATCH = 0;
    int32 index = vector_max(vline) - 1;
    int32 lcd = 0;
    vector cmd_vector = NULL;
    vector matchvec = NULL;
    ctc_cmd_element_t* cmd_element = NULL;
    ctc_match_type_t match = 0;
    char** match_str = NULL;

    int32 best_match_type = 0;
    unsigned short matched_count[3] = {0};
    char* CTC_PARTLY_MATCH_element = NULL;
    char* CTC_EXTEND_MATCH_element = NULL;

    if (vector_slot(vline, 0) == NULL)
    {
        *status = CMD_ERR_NOTHING_TODO;
        return match_str;
    }

    CTC_PARTLY_MATCH_element = (char*)sal_alloc(sizeof(char) * MAX_ELEMENT_NUM, "clicmd");
    CTC_EXTEND_MATCH_element = (char*)sal_alloc(sizeof(char) * MAX_ELEMENT_NUM, "clicmd");
    if (!CTC_PARTLY_MATCH_element || !CTC_EXTEND_MATCH_element)
    {
        ctc_cli_out("Error: no memory!!\n\r");
        return NULL;
    }
    sal_memset(CTC_PARTLY_MATCH_element, 0, sizeof(char) * MAX_ELEMENT_NUM);
    sal_memset(CTC_EXTEND_MATCH_element, 0, sizeof(char) * MAX_ELEMENT_NUM);

    /* Make copy of command elements. */
    cmd_vector = ctc_vti_vec_copy(ctc_cmd_node_vector(cmdvec, vti->node));
    if (!cmd_vector)
    {
        ctc_cli_out("Error: no memory!!\n\r");
        return NULL;
    }

    /* filter command elements */

    for (i = 0; i < vector_max(cmd_vector); i++)
    {
        match = 0;
        cmd_element = vector_slot(cmd_vector, i);
        if_CTC_EXACT_MATCH = 1;
        if (cmd_element)
        {
            match = ctc_cmd_filter_by_completion(cmd_element->strvec, vline, matched_desc_ptr, &if_CTC_EXACT_MATCH);
            if (!match)
            {
                vector_slot(cmd_vector, i) = NULL;
                if (cmd_debug)
                {
                    ctc_cli_out("cmd element %d filtered \n\r", i);
                }
            }
            else
            {
                best_match_type = ctc_cmd_best_match_check(vline, matched_desc_ptr, 1);
                matched_count[best_match_type]++;
                if (best_match_type == CTC_CMD_PARTLY_MATCH)
                {
                    CTC_PARTLY_MATCH_element[i] = 1;
                    CTC_EXTEND_MATCH_element[i] = 0;
                }
                else if (best_match_type == CTC_CMD_EXTEND_MATCH)
                {
                    CTC_EXTEND_MATCH_element[i] = 1;
                    CTC_PARTLY_MATCH_element[i] = 0;
                }
                else
                {
                    CTC_EXTEND_MATCH_element[i] = 0;
                    CTC_PARTLY_MATCH_element[i] = 0;
                }

                if (cmd_debug)
                {
                    ctc_cli_out("cmd element %d best match %d: %s \n\r", i, best_match_type, cmd_element->string);
                }
            }
        }
    } /* for cmd filtering */

    if (matched_count[CTC_CMD_EXACT_MATCH]) /* found exact match, filter all partly and extend match elements */
    {
        for (i = 0; i < vector_max(cmd_vector); i++)
        {
            if (CTC_EXTEND_MATCH_element[i] || CTC_PARTLY_MATCH_element[i]) /* filter all other elements */
            {
                vector_slot(cmd_vector, i) = NULL;
                if (cmd_debug)
                {
                    ctc_cli_out("cmd element %d filterd for not exact match \n\r", i);
                }
            }
        }
    }
    else if (matched_count[CTC_CMD_PARTLY_MATCH]) /* found partly match, filter all extend match elements */
    {
        for (i = 0; i < vector_max(cmd_vector); i++)
        {
            if (CTC_EXTEND_MATCH_element[i]) /* filter all other elements */
            {
                vector_slot(cmd_vector, i) = NULL;
                if (cmd_debug)
                {
                    ctc_cli_out("cmd element %d filterd for not exact match \n\r", i);
                }
            }
        }
    }

    sal_free(CTC_PARTLY_MATCH_element);
    sal_free(CTC_EXTEND_MATCH_element);

    /* Prepare match vector. */
    matchvec = ctc_vti_vec_init(INIT_MATCHVEC_SIZE);
    if (!matchvec)
    {
        *status = CMD_WARNING;
        return NULL;
    }

    matchvec = ctc_cmd_describe_complete_cmd(vline, cmd_vector, matchvec, 0);

    /* We don't need cmd_vector any more. */
    ctc_vti_vec_free(cmd_vector);

    /* No matched command */
    if (vector_slot(matchvec, 0) == NULL)
    {
        ctc_vti_vec_free(matchvec);

        /* In case of 'command \t' pattern.  Do you need '?' command at
         the end of the line. */
        if (vector_slot(vline, index) == '\0')
        {
            *status = CMD_ERR_NOTHING_TODO;
        }
        else
        {
            *status = CMD_ERR_NO_MATCH;
        }

        return NULL;
    }

    /* Only one matched */
    if (vector_slot(matchvec, 1) == NULL)
    {
        match_str = (char**)matchvec->index;
        ctc_vti_vec_only_wrapper_free(matchvec);
        if ((sal_strcmp(match_str[0], "<cr>") == 0) || CTC_CMD_VARIABLE(match_str[0])) /* if only cr or VAR matched, dont show it*/
        {
            sal_free(match_str);
            *status = CMD_ERR_NOTHING_TODO;
            return NULL;
        }

        *status = CMD_COMPLETE_FULL_MATCH;
        return match_str;
    }

    /* Make it sure last element is NULL. */
    ctc_vti_vec_set(matchvec, NULL);

    /* Check LCD of matched strings. */
    if (vector_slot(vline, index) != NULL)
    {
        lcd = ctc_cmd_lcd((char**)matchvec->index);

        if (lcd)
        {
            int32 len = sal_strlen(vector_slot(vline, index));

            if (len < lcd)
            {
                char* lcdstr;

                lcdstr = sal_alloc(lcd + 1, "clicmd");
                sal_memcpy(lcdstr, matchvec->index[0], lcd);
                lcdstr[lcd] = '\0';

                /* match_str =(char **) &lcdstr; */

                /* Free matchvec. */
                for (i = 0; i < vector_max(matchvec); i++)
                {
                    if (vector_slot(matchvec, i))
                    {
                        sal_free(vector_slot(matchvec, i));
                    }
                }

                ctc_vti_vec_free(matchvec);

                /* Make new matchvec. */
                matchvec = ctc_vti_vec_init(INIT_MATCHVEC_SIZE);
                ctc_vti_vec_set(matchvec, lcdstr);
                match_str = (char**)matchvec->index;
                ctc_vti_vec_only_wrapper_free(matchvec);

                *status = CMD_COMPLETE_MATCH;
                return match_str;
            }
        }
    }

    match_str = (char**)matchvec->index;
    ctc_vti_vec_only_wrapper_free(matchvec);
    *status = CMD_COMPLETE_LIST_MATCH;
    return match_str;

}

ctc_match_type_t
ctc_cmd_is_cmd_incomplete(vector str_vec, vector vline, ctc_cmd_desc_t** matched_desc_ptr, int32* if_CTC_EXACT_MATCH)
{
    int32 index = 0;
    ctc_match_type_t match = 0;

    match = ctc_cmd_filter_command_tree(str_vec, vline, &index, matched_desc_ptr, 0, if_CTC_EXACT_MATCH);

    return match;
}
void *sal_realloc(void *ptr, size_t size)
{
    void *new_ptr = NULL;
    if (ptr) 
    {
        if (size != 0) 
        {
            if (!(new_ptr = sal_alloc(size, "clicmd")))
            {
                return NULL;
            }
            memmove(new_ptr, ptr, size);
        }

        sal_free(ptr);
    }
    else 
    {
        if (size != 0)
        {
            if (!(new_ptr = sal_alloc(size, "clicmd")))
            {
                return NULL;
            }
        }
    }

    return new_ptr;
}
/* Execute command by argument vline vector. */
int32
ctc_cmd_execute_command(vector vline, ctc_vti_t* vti, ctc_cmd_element_t** cmd)
{
    int32 i = 0;
    int32 if_CTC_EXACT_MATCH = 0;
    int32 best_match_type = 0;
    vector cmd_vector = NULL;
    ctc_cmd_element_t* cmd_element = NULL;
    ctc_cmd_element_t* matched_element = NULL;
    unsigned short matched_count[4] = {0};
    int32 matched_index[4] = {0};
    int32 argc;
    char** argv;
    int32 ret = 0;
    ctc_match_type_t match = 0;

    argv = (void*)sal_alloc(CMD_ARGC_MAX*sizeof(void*), "clicmd");
    if (NULL == argv)
    {
        return -1;
    }
    

    /* Make copy of command elements. */
    cmd_vector = ctc_vti_vec_copy(ctc_cmd_node_vector(cmdvec, vti->node));
    if (!cmd_vector)
    {
        ret = CMD_SYS_ERROR;
        goto error;
    }

    /* filter command elements */
    for (i = 0; i < vector_max(cmd_vector); i++)
    {
        match = 0;
        cmd_element = vector_slot(cmd_vector, i);
        if (cmd_element)
        {
            match = ctc_cmd_filter_by_completion(cmd_element->strvec, vline, matched_desc_ptr, &if_CTC_EXACT_MATCH);
            if (!match)
            {
                vector_slot(cmd_vector, i) = NULL;
                if (cmd_debug)
                {
                    ctc_cli_out("cmd: %d: filtered \n\r", i);
                }
            }
            else
            {
                if (cmd_debug)
                {
                    ctc_cli_out("cmd: %d matched type: %d: %s \n\r", i, match, cmd_element->string);
                }

                if (CTC_INCOMPLETE_CMD == match)
                {
                    matched_count[CTC_CMD_IMCOMPLETE_MATCH]++;
                }
                else
                {
                    best_match_type = ctc_cmd_best_match_check(vline, matched_desc_ptr, 0);
                    matched_index[best_match_type] = i;
                    matched_count[best_match_type]++;
                }
            }
        }
    }

    if (!matched_count[CTC_CMD_EXACT_MATCH] && !matched_count[CTC_CMD_PARTLY_MATCH]
        && !matched_count[CTC_CMD_EXTEND_MATCH] && !matched_count[CTC_CMD_IMCOMPLETE_MATCH])
    {
        ctc_vti_vec_free(cmd_vector);
        ret = CMD_ERR_NO_MATCH;
        goto error;
    }

    if (matched_count[CTC_CMD_IMCOMPLETE_MATCH] && !matched_count[CTC_CMD_EXACT_MATCH] && !matched_count[CTC_CMD_PARTLY_MATCH]
        && !matched_count[CTC_CMD_EXTEND_MATCH])
    {
        ctc_vti_vec_free(cmd_vector);
        ret = CMD_ERR_INCOMPLETE;
        goto error;
    }

    if ((matched_count[CTC_CMD_EXACT_MATCH] > 1) ||
        (!matched_count[CTC_CMD_EXACT_MATCH]  && (matched_count[CTC_CMD_PARTLY_MATCH] > 1 || matched_count[CTC_CMD_EXTEND_MATCH] > 1) )) /* exact match found, can be 1 or more */
    {
        ctc_vti_vec_free(cmd_vector);
        ret = CMD_ERR_AMBIGUOUS;
        goto error;
    }


    if (matched_count[CTC_CMD_EXACT_MATCH]) /* single match */
    {
        matched_element = vector_slot(cmd_vector, matched_index[CTC_CMD_EXACT_MATCH]);
    }
    else if (matched_count[CTC_CMD_PARTLY_MATCH])
    {
        matched_element = vector_slot(cmd_vector, matched_index[CTC_CMD_PARTLY_MATCH]);
    }
    else
    {
        matched_element = vector_slot(cmd_vector, matched_index[CTC_CMD_EXTEND_MATCH]);
    }

    ctc_vti_vec_free(cmd_vector);

    /*retry to get new desc */
    ctc_cmd_is_cmd_incomplete(matched_element->strvec, vline, matched_desc_ptr, &if_CTC_EXACT_MATCH);

    /* Argument treatment */
    argc = 0;

    for (i = 0; i < vector_max(vline); i++)
    {
        ctc_cmd_desc_t* desc = matched_desc_ptr [i];
        if (desc->is_arg)
        {
            if (!CTC_CMD_VARIABLE(desc->cmd)) /* keywords, use origina, user input can be partiall */
            {
                char* cp = vector_slot(vline, i);
                if (cp)
                {
                    cp = sal_realloc(cp, sal_strlen(desc->cmd) + 1);
                    vector_slot(vline, i) = cp; /* cp changed,  must be freed*/
                    sal_memcpy(cp, desc->cmd, sal_strlen(desc->cmd));
                    cp[sal_strlen(desc->cmd)] = '\0';
                }
            }

            argv[argc++] = vector_slot(vline, i);
        }

        if (argc >= CMD_ARGC_MAX)
        {
            ret = CMD_ERR_EXEED_ARGC_MAX;
            goto error;            
        }
    }

    /* For vtysh execution. */
    if (cmd)
    {
        *cmd = matched_element;
    }

    if (cmd_arg_debug)
    {
        ctc_cli_out("argc=%d, argv= \n\r", argc);

        for (i = 0; i < argc; i++)
        {
            ctc_cli_out("%s ", argv[i]);
        }

        ctc_cli_out("\n\r");
    }

    ret = (*matched_element->func)(matched_element, vti, argc, argv);
error:
    sal_free(argv);
    
    /* Execute matched command. */
    return ret;
}

/* Execute command by argument readline. */
int32
ctc_cmd_execute_command_strict(vector vline, ctc_vti_t* vti, ctc_cmd_element_t** cmd)
{
    int32 i;
    int32 index;
    vector cmd_vector;
    ctc_cmd_element_t* cmd_element;
    ctc_cmd_element_t* matched_element;
    uint32 matched_count, incomplete_count;
    int32 argc;
    char* argv[CMD_ARGC_MAX];
    int32 varflag;
    ctc_match_type_t match = 0;
    char* command;

    /* Make copy of command element */
    cmd_vector = ctc_vti_vec_copy(ctc_cmd_node_vector(cmdvec, vti->node));
    if (!cmd_vector)
    {
        return CMD_SYS_ERROR;
    }

    for (index = 0; index < vector_max(vline); index++)
    {
        int32 ret;

        command = vector_slot(vline, index);

        match = ctc_cmd_filter_by_string(vector_slot(vline, index),
                                         cmd_vector, index);

        /* If command meets '.VARARG' then finish matching. */
        if (match == CTC_VARARG_MATCH)
        {
            break;
        }

        ret = is_cmd_ambiguous(command, cmd_vector, index, match);
        if (ret == 1)
        {
            ctc_vti_vec_free(cmd_vector);
            return CMD_ERR_AMBIGUOUS;
        }

        if (ret == 2)
        {
            ctc_vti_vec_free(cmd_vector);
            return CMD_ERR_NO_MATCH;
        }
    }

    /* Check matched count. */
    matched_element = NULL;
    matched_count = 0;
    incomplete_count = 0;

    for (i = 0; i < vector_max(cmd_vector); i++)
    {
        if (vector_slot(cmd_vector, i) != NULL)
        {
            cmd_element = vector_slot(cmd_vector, i);

            if (match == CTC_VARARG_MATCH || index >= cmd_element->cmdsize)
            {
                matched_element = cmd_element;
                matched_count++;
            }
            else
            {
                incomplete_count++;
            }
        }
    }

    /* Finish of using cmd_vector. */
    ctc_vti_vec_free(cmd_vector);

    /* To execute command, matched_count must be 1.*/
    if (matched_count == 0)
    {
        if (incomplete_count)
        {
            return CMD_ERR_INCOMPLETE;
        }
        else
        {
            return CMD_ERR_NO_MATCH;
        }
    }

    if (matched_count > 1)
    {
        return CMD_ERR_AMBIGUOUS;
    }

    /* Argument treatment */
    varflag = 0;
    argc = 0;

    for (i = 0; i < vector_max(vline); i++)
    {
        if (varflag)
        {
            argv[argc++] = vector_slot(vline, i);
        }
        else
        {
            vector descvec = vector_slot(matched_element->strvec, i);

            if (vector_max(descvec) == 1)
            {
                ctc_cmd_desc_t* desc = vector_slot(descvec, 0);
                char* str = desc->cmd;

                if (CTC_CMD_VARARG(str))
                {
                    varflag = 1;
                }

                if (varflag || CTC_CMD_VARIABLE(str) || CTC_CMD_OPTION(str))
                {
                    argv[argc++] = vector_slot(vline, i);
                }
            }
            else
            {
                argv[argc++] = vector_slot(vline, i);
            }
        }

        if (argc >= CMD_ARGC_MAX)
        {
            return CMD_ERR_EXEED_ARGC_MAX;
        }
    }

    /* For vtysh execution. */
    if (cmd)
    {
        *cmd = matched_element;
    }

    if (matched_element->daemon)
    {
        return CMD_SUCCESS_DAEMON;
    }

    /* Now execute matched command */
    return (*matched_element->func)(matched_element, vti, argc, argv);
}

/* Initialize command interface. Install basic nodes and commands. */
void
ctc_cmd_init(int32 terminal)
{
    /* Allocate initial top vector of commands. */
    cmdvec = ctc_vti_vec_init(VECTOR_MIN_SIZE);
    matched_desc_ptr = (ctc_cmd_desc_t**)sal_alloc(sizeof(ctc_cmd_desc_t*) * CMD_ARGC_MAX, "clicmd");
    if (!cmdvec || !matched_desc_ptr)
    {
        ctc_cli_out("\nError: no memory!!");
    }
    sal_memset(matched_desc_ptr, 0 , sizeof(ctc_cmd_desc_t*) * CMD_ARGC_MAX);
}

void
ctc_cli_enable_cmd_debug(int32 enable)
{
    cmd_debug = enable ? 1 : 0;
}

void
ctc_cli_enable_arg_debug(int32 enable)
{
    cmd_arg_debug = enable ? 1 : 0;
}

int32
ctc_is_cmd_var(char* cmd)
{
    int32 index = 0;

    if (cmd[0] == '<')
    {
        return 1;
    }

    for (index = 0; index < sal_strlen(cmd); index++)
    {
        if ((cmd[index] >= 'A') && (cmd[index] <= 'Z'))
        {
            return 1;
        }
    }

    return 0;
}

