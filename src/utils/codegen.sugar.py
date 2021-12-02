# SPDX-License-Identifier: Apache-2.0
# Copyright 2017 Eotvos Lorand University, Budapest, Hungary

from inspect import getmembers, isfunction
import sys

from compiler_log_warnings_errors import addWarning, addError
from compiler_common import types, with_base, resolve_reference, is_subsequent, groupby, group_references, fldid, fldid2, pp_type_16, make_const, SugarStyle, prepend_statement, append_statement, is_control_local_var, generate_var_name, pre_statement_buffer, post_statement_buffer, enclosing_control, unique_everseen
from hlir16.hlir_attrs import simple_binary_ops, complex_binary_ops
from itertools import takewhile

################################################################################

def type_to_str(t):
    if t.node_type == 'Type_Bits':
        sign = 'int' if t.isSigned else 'uint'
        return f'{sign}{t.size}_t'
    return f'{t.name}_t'

def gen_format_type(t, resolve_names = True, use_array = False, addon = ""):
    """Returns a type. If the type has a part that has to come after the variable name in a declaration,
    such as [20] in uint8_t varname[20], it should be separated with a space."""

    if t.node_type == 'Type_Specialized':
        extern_name = t.baseType.path.name

        # TODO is there a more straightforward way to deal with such externs?
        argtyped_externs = ["Digest"]

        if extern_name in argtyped_externs:
            #[ ${t.arguments[0].urtype.name}
        else:
            # types for externs (smems)
            params = t.urtype.typeParameters.parameters

            postfix_types = (par.urtype for par in params if par is not None)
            postfix = ''.join((f'_{type_to_str(pt)}' for pt in postfix_types if pt is not None))
            #[ ${extern_name}${postfix}
    elif t.node_type == 'Type_Void':
        #[ void
    elif t.node_type == 'Type_Boolean':
        #[ bool
    elif t.node_type == 'Type_Bits':
        size = 8 if t.size <= 8 else 16 if t.size <= 16 else 32 if t.size <= 32 else 8
        base = f'int{size}_t' if t.isSigned else f'uint{size}_t'
        if use_array:
            #[ $base $addon[(${t.size} + 7) / 8]
        else:
            ptr = '*' if t.size > 32 else ''
            #[ $base$ptr $addon
    elif t.node_type == 'Type_Enum':
        short_name = t.c_name[:-2] if t.c_name.endswith('_t') else t.c_name
        #[ ${short_name}_t
    elif t.node_type == 'Type_Var' and t.urtype.name in types.env():
        #[ ${types.env()[t.urtype.name]}
    elif t.node_type == 'Type_Name':
        t2 = t.urtype
        if not resolve_names:
            #[ ${t2.name}
        else:
            #= gen_format_type(t2, resolve_names, use_array, addon)
    elif t.node_type == 'Type_Extern':
        #[ ${t.name}_t
    elif t.node_type == 'Type_Struct':
        base_name = re.sub(r'_t$', '', t.name)
        #[ struct ${base_name}_s
    elif t.node_type == 'Type_Varbits':
        #[ uint8_t [${(t.size+7)//8}] /* preliminary type for varbits */
    elif t.node_type == 'Type_Error':
        #[ ${t.c_name}_t
    elif t.node_type == 'Type_List':
        #[ bitfield_handle_t
    else:
        addError('formatting type', f'Type {t.node_type} for node ({t}) is not supported yet!')
        #[ TODO_TYPE_FOR_${t.name} /* placeholder type for ${t.node_type} */

def gen_format_type_mask(t):
    if t.node_type == 'Type_Bits' and not t.isSigned:
        mask = hex((2 ** t.size) - 1)
        #[ $mask&
    else:
        addError('formatting a type mask', 'Currently only bit<w> is supported!')

def gen_format_declaration(d, varname_override):
    var_name = d.name if varname_override is None else varname_override

    if d.node_type == 'Declaration_Variable':
        if d.urtype.node_type == 'Type_Header':
            # Data for variable width headers is stored in parser_state_t
            pass
        elif d.urtype.node_type == 'Type_Boolean':
            #[ bool ${var_name} = false;
        else:
            t = gen_format_type(d.type, False)
            #[ $t ${var_name};
    elif d.node_type == 'Declaration_Instance':
        t = f'{gen_format_type(d.type, False)}_t'
        #[ extern void ${t}_init(${t}*);
        #[ $t ${var_name};
        #[ ${t}_init(&${var_name});
    elif d.node_type in ('P4Table', 'P4Action'):
        #[ /* nothing */
    else:
        addError('formatting declaration', f'Declaration of type {d.node_type} is not supported yet!')

################################################################################

def int_to_big_endian_byte_array_with_length(value, width, base=10):
    array = []
    while value > 0:
        array.append(int(value % 256))
        value /= 256
    array.reverse()
    array_len = len(array)
    padded_array = [0 for i in range(width-array_len)] + array[array_len-min(array_len, width) : array_len]
    return '{' + ', '.join([with_base(x, base) for x in padded_array]) + '}'


def bit_bounding_unit(t):
    """The bit width of the smallest int that can contain the type,
    or the string "bytebuf" if it is larger than all possible container types."""
    if t.size <= 8:
        return "8"
    if t.size <= 16:
        return "16"
    if t.size <= 32:
        return "32"
    return "bytebuf"

def member_to_hdr_fld_info(member_expr):
    if member_expr.urtype.node_type == 'Type_Varbits' and 'member' not in member_expr.expr:
        return member_expr.expr.path.name, member_expr.member

    hdrname = "all_metadatas" if member_expr.expr.hdr_ref('is_metadata', False) else member_expr.expr.member if 'member' in member_expr.expr else member_expr.member
    if 'member' not in member_expr.expr:
        return hdrname, None
    return hdrname, member_expr.member


def member_to_hdr_fld(member_expr):
    hdrname, fldname = member_to_hdr_fld_info(member_expr)
    # assert fldname is not None, f"Expression {member_expr} refers to header {hdrname} but no field reference found"
    if fldname is None:
        return f'HDR({hdrname})', None
    return f'HDR({hdrname})', f'FLD({hdrname},{fldname})'

def member_to_fld_name(member_expr):
    hdrname, fldname = member_to_hdr_fld_info(member_expr)
    return f'FLD({hdrname},{fldname})'


def gen_extern_format_parameter(expr, par, packets_or_bytes_override = None):
    # TODO
    # if packets_or_bytes_override:
    if par.direction == "in" or expr.node_type != "Member":
        prefix = "&" if par.direction != "in" and par.type.node_type != 'Type_Bits' else ""
        #[ $prefix(${format_expr(expr, format_as_value=True, expand_parameters=True)})
    else:
        expr_width = expr.type.size

        hdrname, fldname = member_to_hdr_fld(expr)
        # hdrname = "all_metadatas" if expr.expr.hdr_ref.urtype.is_metadata else expr.expr.member if 'member' in expr.expr else expr.member
        # fldname = member_to_fld_name(expr)

        varname = generate_var_name()

        if fldname is None:
            #pre[ uint8_t* $varname;
            #[ $varname
        else:
            if expr_width<=32:
                expr_unit = bit_bounding_unit(expr.type)
                #pre[ uint${expr_unit}_t $varname;
                if par.direction=="inout":
                    #pre[ $varname = ${format_expr(expr)};
                #aft[ set_field((fldT[]){{pd, HDR($hdrname), ${fldname} }}, 0, $varname, ${expr_width});
                #[ &$varname
            else:
                #pre[ uint8_t $varname[${(int)((expr_width+7)//8)}];
                if par.direction=="inout":
                    #pre[ EXTRACT_BYTEBUF_PACKET(pd, HDR(${hdrname}), ${fldname}, $varname);
                #aft[ MODIFY_BYTEBUF_BYTEBUF_PACKET(pd, HDR(${hdrname}), ${fldname}, $varname, ${expr_width});
                #[ $varname

def gen_format_statement_ref_wide(dst, src, dst_width, dst_is_vw, dst_bytewidth, dst_name, dst_hdr_name, dst_fld_name):
    global src_pointer
    if src.node_type == 'Member':
        src_pointer = generate_var_name('tmp_fldref')
        #[ uint8_t $src_pointer[$dst_bytewidth];

        if 'fld_ref' in src:
            hdrinst = 'all_metadatas' if src.expr.type.is_metadata else src.expr.member
            #[ EXTRACT_BYTEBUF_PACKET(pd, HDR(${hdrinst}), ${member_to_fld_name(src)}, ${src_pointer})
            if dst_is_vw:
                src_vw_bitwidth = f'pd->headers[HDR({src.expr.member})].var_width_field_bitwidth'
                dst_bytewidth = f'({src_vw_bitwidth}/8)'
        else:
            # TODO delete? srcname = src.expr.decl_ref.name
            srcname = src.expr.hdr_ref.name
            # breakpoint()
            #[ EXTRACT_BYTEBUF_BUFFER(pstate->${srcname}, pstate->${srcname}_var, ${member_to_fld_name(src)}, $src_pointer)
            if dst_is_vw:
                src_vw_bitwidth = f'pstate->{src.expr.hdr_ref.name}_var'
                dst_bytewidth = f'({src_vw_bitwidth}/8)'
    elif src.node_type == 'PathExpression':
        name = src.path.name
        refbase = "local_vars->" if is_control_local_var(name) else 'parameters->'
        src_pointer = f'{refbase}{name}'
    elif src.node_type == 'Constant':
        src_pointer = generate_var_name('tmp_fldref_const')
        #[ uint8_t $src_pointer[$dst_bytewidth] = ${int_to_big_endian_byte_array_with_length(src.value, dst_bytewidth, src.base)};
    elif src.node_type == 'Mux':
        src_pointer = generate_var_name('tmp_fldref_mux')
        #[ uint8_t $src_pointer[$dst_bytewidth] = ((${format_expr(src.e0.left)}) == (${format_expr(src.e0.right)})) ? (${format_expr(src.e1)}) : (${format_expr(src.e2)});
    else:
        src_pointer = 'NOT_SUPPORTED'
        addError('formatting statement', f'Assignment to unsupported field in: {format_expr(dst)} = {src}')

def gen_format_statement_fieldref_wide(dst, src, dst_width, dst_is_vw, dst_bytewidth, dst_name, dst_hdr_name, dst_fld_name):
    global src_pointer
    src_pointer = ''
    #= gen_format_statement_ref_wide(dst, src, dst_width, dst_is_vw, dst_bytewidth, dst_name, dst_hdr_name, dst_fld_name)

    if dst_is_vw:
        dst_fixed_size = dst.expr.hdr_ref.urtype.size - dst.fld_ref.size
        #[ pd->headers[$dst_hdr_name].var_width_field_bitwidth = get_var_width_bitwidth(pstate);
        #[ pd->headers[$dst_hdr_name].length = ($dst_fixed_size + pd->headers[$dst_hdr_name].var_width_field_bitwidth)/8;

    #[ MODIFY_BYTEBUF_BYTEBUF_PACKET(pd, $dst_hdr_name, $dst_fld_name, $src_pointer, $dst_bytewidth)

    #[ dbg_bytes($src_pointer, $dst_bytewidth,
    #[      "    " T4LIT(=,field) " Modifying field " T4LIT(%s,header) "." T4LIT(%s,field) "/" T4LIT(%db) " (" T4LIT(%d) "B) = ",
    #[      header_instance_names[$dst_hdr_name],
    #[      field_names[$dst_fld_name], // $dst_fld_name
    #[      $dst_bytewidth*8,
    #[      $dst_bytewidth
    #[      );


def gen_format_statement_parameter_wide(dst, src, dst_width, dst_is_vw, dst_bytewidth, dst_name, dst_hdr_name, dst_fld_name):
    global src_pointer
    src_pointer = ''
    #= gen_format_statement_ref_wide(dst, src, dst_width, dst_is_vw, dst_bytewidth, dst_name, dst_hdr_name, dst_fld_name)

    if dst_is_vw:
        addError("Error formatting parameter expression", "Varbit is not supported for parameter assignment")
        return ''
    refbase = "local_vars->" if is_control_local_var(dst.decl_ref.name) else 'parameters->'
    dst_pointer = '{}{}'.format(refbase, dst.decl_ref.name)
    # src_pointer is array in this case
    #[ memcpy(&($dst_pointer), $src_pointer, $dst_bytewidth);


def is_primitive(typenode):
    """Returns true if the argument node is compiled to a non-reference C type."""
    # TODO determine better if the source is a reference or not
    return typenode.node_type == "Type_Boolean" or (typenode.node_type == 'Type_Bits' and typenode.size <= 32)

def gen_format_statement_ref_short(dst, src, dst_width, dst_is_vw, dst_bytewidth, dst_name, dst_hdr_name, dst_fld_name, varname='value32'):
    if src.node_type == 'PathExpression':
        indirection = "&" if is_primitive(src.type) else ""
        var_name = src.path.name
        refbase = "local_vars->" if is_control_local_var(src.decl_ref.name) else 'parameters->'
        #[ memcpy(&$varname, $indirection($refbase${var_name}), $dst_bytewidth);
    else:
        #[ $varname = ${format_expr(src)};


def gen_format_statement_parameter_short(dst, src, dst_width, dst_is_vw, dst_bytewidth, dst_name, dst_hdr_name, dst_fld_name, varname='value32'):
    varname = 'value32'
    #= gen_format_statement_ref_short(dst, src, dst_width, dst_is_vw, dst_bytewidth, dst_name, dst_hdr_name, dst_fld_name, varname)
    indirection = "&" if is_primitive(dst.type) else ""
    refbase = "local_vars->" if is_control_local_var(dst.decl_ref.name) else 'parameters->'
    #[ memcpy($indirection($refbase${dst.decl_ref.name}), &$varname, $dst_bytewidth);


def gen_format_statement_fieldref_short(dst, src, dst_width, dst_is_vw, dst_bytewidth, dst_name, dst_hdr_name, dst_fld_name):
    varname = 'value32'
    #= gen_format_statement_ref_short(dst, src, dst_width, dst_is_vw, dst_bytewidth, dst_name, dst_hdr_name, dst_fld_name, varname)

    #[ // MODIFY_INT32_INT32_AUTO_PACKET(pd, $dst_hdr_name, $dst_fld_name, $varname)
    #[ set_field((fldT[]){{pd, $dst_hdr_name, $dst_fld_name}}, 0, $varname, $dst_width);


def gen_format_statement_fieldref(dst, src):
    #TODO: handle preparsed fields, width assignment for vw fields and assignment to buffer instead header fields
    dst_width, dst_is_vw, dst_bytewidth = extract_sizes(dst, src)

    dst_name = dst.expr.member if dst.expr.node_type == 'Member' else dst.expr.path.name if dst.expr('hdr_ref', lambda h: h.urtype.is_metadata) else dst.expr._hdr_ref._path.name
    dst_hdr_name, dst_fld_name = member_to_hdr_fld(dst)

    if dst_width <= 32:
        #= gen_format_statement_fieldref_short(dst, src, dst_width, dst_is_vw, dst_bytewidth, dst_name, dst_hdr_name, dst_fld_name)
    else:
        #= gen_format_statement_fieldref_wide(dst, src, dst_width, dst_is_vw, dst_bytewidth, dst_name, dst_hdr_name, dst_fld_name)

def gen_format_statement_parameter(dst, src):
    dst_width, dst_is_vw, dst_bytewidth = extract_sizes(dst, src)

    if dst_width <= 32:
        #= gen_format_statement_parameter_short(dst, src, dst_width, dst_is_vw, dst_bytewidth, "", "", "")
    else:
        #= gen_format_statement_parameter_wide(dst, src, dst_width, dst_is_vw, dst_bytewidth, "", "", "")

def extract_sizes(dst, src):
    dst_width = dst.type.size
    dst_is_vw = dst.type.node_type == 'Type_Varbits'
    dst_bytewidth = (dst_width+7)//8

    assert(dst_width == src.type.size)
    assert(dst_is_vw == (src.type.node_type == 'Type_Varbits'))

    return dst_width, dst_is_vw, dst_bytewidth


def is_atomic_block(blckstmt):
    try:
        return any(blckstmt.annotations.annotations.filter('name', 'atomic'))
    except:
        return False


# TODO should be improved
def needs_defererencing(dst, src):
    return src.node_type != dst.node_type and src.node_type not in ('Constant', 'Member')


def gen_do_assignment(dst, src):
    if dst.type.node_type == 'Type_Header':
        src_hdr_name = src.path.name if src.node_type == 'PathExpression' else src.member
        dst_hdr_name = dst.path.name if dst.node_type == 'PathExpression' else dst.member

        #[ memcpy(pd->headers[HDR(${dst_hdr_name})].pointer, pd->headers[HDR(${src_hdr_name})].pointer, hdr_infos[HDR(${src_hdr_name})].byte_width);
        #[ dbg_bytes(pd->headers[HDR(${dst_hdr_name})].pointer, hdr_infos[HDR(${src_hdr_name})].byte_width, "    : " T4LIT(dst_hdr_name,header) "/" T4LIT(%dB) " = " T4LIT(src_hdr_name,header) " = ", hdr_infos[HDR(${src_hdr_name})].byte_width);
    elif dst.type.node_type == 'Type_Bits':
        # TODO refine the condition to find out whether to use an assignment or memcpy
        requires_memcpy = src.type.size > 32 or 'decl_ref' in dst
        # is_assignable = src.type.size in [8, 32]
        is_assignable = src.type.size <= 32

        if src.type.node_type == 'Type_Bits' and not requires_memcpy:
            dereference = "*" if needs_defererencing(dst, src) else ""

            if is_assignable:
                if dst("expr.hdr_ref.urtype.is_metadata") or dst("hdr_ref.urtype.is_metadata"):
                    fldname = dst.member if dst("expr.hdr_ref.urtype.is_metadata") else dst.field_name
                    #[ set_field((fldT[]){{pd, HDR(all_metadatas), FLD(all_metadatas,$fldname)}}, 0, ($dereference(${format_expr(src, expand_parameters=True)})), ${dst.urtype.size});
                    #[ debug("       : " T4LIT(all_metadatas,header) "." T4LIT($fldname,field) "/" T4LIT(%d) " = " T4LIT(%d,bytes) " (" T4LIT(%${(src.type.size+7)//8}x,bytes) ")\n", ${dst.urtype.size}, $dereference(${format_expr(src, expand_parameters=True)}), $dereference(${format_expr(src, expand_parameters=True)}));
                elif dst.node_type == 'Slice':
                    #[ // TODO assignment to slice
                else:
                    #[ /* ${src.node_type} ${dst.node_type} */
                    #[ ${format_expr(dst)} = (${format_type(dst.type)})($dereference(${format_expr(src, expand_parameters=True)}));
                    if dst.node_type == 'Member':
                        if dst.urtype('is_metadata', False):
                            # Note: the metadata header and field name is joined by underscores, separating them as best as possible
                            hdrname = "all_metadatas"
                            fldname = nameparts[-1]
                        else:
                            hdrname = dst.expr._expr.path.name
                            fldname = dst.member
                        #[ debug("       : " T4LIT($hdrname,header) "." T4LIT($fldname,field) " = " T4LIT(%d,bytes) " (" T4LIT(%${(src.type.size+7)//8}x,bytes) ")\n", ${format_expr(dst)}, ${format_expr(dst)});
                    else:
                        #[ debug("       : " T4LIT(${format_expr(dst)},header) " = " T4LIT(%d,bytes) " (" T4LIT(%${(src.type.size+7)//8}x,bytes) ")\n", ${format_expr(dst)}, ${format_expr(dst)});
            else:
                tmpvar = generate_var_name()

                if 'decl_ref' in dst:
                    addError("Assigning variable", f"Variable {dst.path.name} is larger than 32 bits, assignment currently unsupported")
                    #[ // TODO something like: ${format_expr(dst)} = ${format_expr(src)};
                else:
                    hdr = dst.expr.hdr_ref
                    fldname = dst.member

                    if dst.type.size <= 32:
                        #[ ${format_expr(dst)} = ${format_expr(src)};
                    else:
                        #[ ${format_type(dst.type)} $tmpvar = (${format_type(dst.type)})(${format_expr(src, expand_parameters=True, needs_variable=True)});
                        #[ MODIFY_BYTEBUF_BYTEBUF_PACKET(pd, HDR(${hdr.name}), FLD(${hdr.name},${fldname}), &$tmpvar, sizeof(${format_type(dst.type)}));
                        #[ dbg_bytes(field_desc(pd, FLD(${hdr.name},${fldname})).byte_addr, sizeof(${format_type(dst.type)}), "        : "T4LIT(${hdr.name},header)"."T4LIT(${fldname},field)"/"T4LIT(%zuB)" = ", sizeof(${format_type(dst.type)}));
        else:
            srcexpr = format_expr(src, expand_parameters=True, needs_variable=True)
            with SugarStyle('no_comment'):
                dsttxt = gen_format_expr(dst)
                srctxt = gen_format_expr(src, expand_parameters=True)
            size = (dst.type.size+7)//8
            #[ memcpy(&(${format_expr(dst)}), &($srcexpr), $size);
            #[ dbg_bytes(&($srcexpr), $size, "    : " T4LIT(%s,header) "/" T4LIT(%dB) " =" T4LIT(%s,header) " = ", "$dsttxt", $size, "$srctxt");
    elif dst.node_type == 'Member':
        tmpvar = generate_var_name('assign_member')
        hdrname = dst.expr.hdr_ref.name
        fldname = dst.member

        #pre[ ${format_type(dst.type)} $tmpvar = ${format_expr(src, expand_parameters=True)};
        #[ MODIFY_INT32_BYTEBUF_PACKET(pd, HDR(${hdrname}), FLD(${hdrname},${fldname}), &$tmpvar, sizeof(${format_type(dst.type)}));
    else:
        #[ ${format_expr(dst)} = ${format_expr(src, expand_parameters=True)};


def is_extract(m):
    return m.member == 'extract' and len(m.type.parameters.parameters) == 1 and m.expr.type.name == 'packet_in'

def gen_format_statement(stmt):
    if stmt.node_type == 'AssignmentStatement':
        dst = stmt.left
        src = stmt.right
        if 'fld_ref' in dst:
            #= gen_format_statement_fieldref(dst, src)
        elif 'decl_ref' in dst:
            #= gen_format_statement_parameter(dst, src)
        else:
            #= gen_do_assignment(dst, src)
    elif stmt.node_type == 'BlockStatement':
        is_atomic = is_atomic_block(stmt)
        if is_atomic:
            #[ LOCK(&${stmt.enclosing_control.type.name}_lock)
        for c in stmt.components:
            #= gen_format_statement(c)
        if is_atomic:
            #[ UNLOCK(&${stmt.enclosing_control.type.name}_lock)
    elif stmt.node_type == 'IfStatement':
        cond = format_expr(stmt.condition)

        # note: the condition may create/use some constants
        pre, post = compiler_common.statement_buffer_value()

        if cond.strip() == '':
            cond = "true"

        #[ ${pre}
        #{ if ($cond) {
        #=     format_statement(stmt.ifTrue)
        if 'ifFalse' in stmt:
            #[ } else {
            #=     format_statement(stmt.ifFalse)
        #} }
        #[ ${post}
    elif stmt.node_type == 'MethodCallStatement':
        mcall = stmt.methodCall
        m = mcall.method

        if 'member' in m and is_extract(m):
            hdrname = stmt.methodCall.arguments[0].expression.member

            # TODO can offset be other than 0 here?

            #pre[ int parser_extract_$hdrname(STDPARAMS);
            #[ parser_extract_$hdrname(STDPARAMS_IN);
            #[ debug("DBGcalling parser_extract_$hdrname\n");
        elif m.node_type == 'Method' and m.name == 'digest':
            mcall = stmt.methodCall
            #= gen_format_methodcall_digest(m, mcall)
        elif 'member' in m and not is_extract(m):
            #= gen_fmt_methodcall(mcall, m)
        else:
            mcall = stmt.methodCall
            #= gen_methodcall(mcall)
    elif stmt.node_type == 'SwitchStatement':
        #[ switch(${format_expr(stmt.expression)}) {
        for case in stmt.cases:
            if case.label.node_type == "DefaultExpression":
                #[ default:
            else:
                #[ case ${format_expr(case.label)}:
            #[   ${format_statement(case.statement)}
            #[   break;
        if [case for case in stmt.cases if case.label.node_type == "DefaultExpression"] == []:
            #[   default: {}
        #[ }

def gen_format_methodcall_digest(m, mcall):
    digest_name = mcall.typeArguments[0].name
    port, fields = mcall.arguments

    #[ struct type_field_list fields;
    #[ fields.fields_quantity = ${len(fields)};
    #[ fields.field_offsets = malloc(sizeof(uint8_t*)*fields.fields_quantity);
    #[ fields.field_widths = malloc(sizeof(uint8_t*)*fields.fields_quantity);

    for idx, f in enumerate(fields.components):
        if f.expr.type.is_metadata:
            #[ fields.field_offsets[$idx] = (uint8_t*) field_desc(pd, FLD(${f.expr.name},${f.member})).byte_addr;
            #[ fields.field_widths[$idx]  =            field_desc(pd, FLD(${f.expr.name},${f.member})).bitwidth;
        else:
            #[ fields.field_offsets[$idx] = (uint8_t*) field_desc(pd, FLD(${f.expr.member},${f.expression.fld_ref.name})).byte_addr;
            #[ fields.field_widths[$idx]  =            field_desc(pd, FLD(${f.expr.member},${f.expression.fld_ref.name})).bitwidth;
    #[ generate_digest(bg,"${digest_name}",0,&fields);
    #[ sleep_millis(DIGEST_SLEEP_MILLIS);

def is_emit(m):
    return m.expr._ref.urtype('name', lambda n: n == 'packet_out')

def gen_isValid(hdr_name):
    #[ controlLocal_tmp_0 = (pd->headers[HDR($hdr_name)].pointer != NULL);

def gen_setValid(hdr_name):
    #{ if (likely(pd->headers[HDR($hdr_name)].pointer == NULL)) {
    #[    pd->headers[HDR($hdr_name)].pointer = (pd->header_tmp_storage + hdr_infos[HDR($hdr_name)].byte_offset);
    #[    pd->is_emit_reordering = true;
    #[    debug("   :: Header instance $$[header]{hdr_name}/" T4LIT(%dB) " set as $$[success]{}{valid}\n", pd->headers[HDR($hdr_name)].length);
    #[ } else {
    #[    debug("   " T4LIT(!!,warning) " Trying to set header instance $$[header]{hdr_name} to $$[success]{}{valid}, but it is already $$[success]{}{valid}\n");
    #} }

def gen_setInvalid(hdr_name):
    #{ if (likely(pd->headers[HDR($hdr_name)].pointer != NULL)) {
    #[    pd->headers[HDR($hdr_name)].pointer = NULL;
    #[    pd->is_emit_reordering = true;
    #[    debug("   :: Header instance $$[header]{hdr_name}/" T4LIT(%dB) " set as $$[status]{}{invalid}\n", pd->headers[HDR($hdr_name)].length);
    #[ } else {
    #[    debug("   " T4LIT(!!,warning) " Trying to set header instance $$[header]{hdr_name} to $$[success]{}{valid}, but it is already $$[success]{}{valid}\n");
    #} }

def gen_emit(mcall):
    arg = mcall.arguments[0]
    hdr = arg.expression.member
    hdr_type = arg.expression.type

    hdr_name = arg.expression.hdr_ref.name if 'hdr_ref' in arg.expression else arg.expression.member

    #[ pd->header_reorder[pd->emit_hdrinst_count] = hdr_infos[HDR($hdr)].idx;
    #[ ++pd->emit_hdrinst_count;

def gen_fmt_methodcall(mcall, m):
    if is_emit(m):
        #= gen_emit(mcall)
    elif 'table_ref' in m.expr and m.member == 'apply':
        #[ ${gen_method_apply(mcall)};
    elif 'member' not in m.expr:
        #= gen_fmt_methodcall_extern(m, mcall)
    else:
        hdr_name = m.expr.member
        specials = ('isValid', 'setValid', 'setInvalid')
        if m.member in specials:
            #= gen_${m.member}(hdr_name)
        else:
            #= gen_methodcall(mcall)

def gen_fmt_methodcall_extern(m, mcall):
    # TODO treat smems and digests separately
    # currently, for legacy reasons, smem_type can take the value 'Digest'
    smem_type = m.expr.decl_ref.smem_type if 'decl_ref' in m.expr and 'smem_type' in m.expr.decl_ref else m.expr.urtype.name

    # if the extern is about both packets and bytes, it takes two separate calls
    is_possibly_multiple = smem_type in ("counter", "meter", "direct_counter", "direct_meter", "Counter")
    if is_possibly_multiple:
        if m.expr.decl_ref.packets_or_bytes == "packets_and_bytes":
            #= gen_format_extern_single(m, mcall, smem_type, is_possibly_multiple, "packets")
            #= gen_format_extern_single(m, mcall, smem_type, is_possibly_multiple, "bytes")
        else:
            #= gen_format_extern_single(m, mcall, smem_type, is_possibly_multiple, m.expr.decl_ref.packets_or_bytes)
    else:
        #= gen_format_extern_single(m, mcall, smem_type, is_possibly_multiple)


def gen_format_extern_single(m, mcall, smem_type, is_possibly_multiple, packets_or_bytes = None):
    extern_name = m.expr.urtype.name
    # TODO funname_postfix
    funname_postfix = ''
    if (m.expr.decl_ref.urtype.name, mcall.method.member) == ('packet_in', 'advance'):
        size = mcall.arguments[0].expression.value
        #[ pd->parsed_length += $size;
        #[ debug("   :: Advancing packet by " T4LIT($size) " bytes\n");
    else:
        args = ", ".join(mcall.method.expr.decl_ref.arguments.map(format_expr))

        #pre[ // TODO declaration
        #[ extern_${extern_name}_${m.member}${funname_postfix}(${args});


def gen_methodcall(mcall):
    m = mcall.method
    mname = m.path.name

    # TODO call    gen_extern_decl(mname, m)   to avoid warnings
    #[ ${format_expr(mcall)};


################################################################################

# A set of expression IDs that have already been generated.
generated_exprs = set()

def convert_component(component):
    if component.node_type == 'Member':
        hdr      = component.expr
        fld_name = component.member
        fld      = hdr.type.fields.get(fld_name)
        return (component.node_type, hdr, fld)

    if component.node_type == 'Constant':
        return (component.node_type, component.value, "")

    addWarning('generating list expression buffer', f'Skipping not supported list element {component}')
    return None

################################################################################

def gen_method_hdr_ref(e):
    # TODO this also should invoke format_expr
    if 'hdr_ref' in e.method.expr:
        return f'HDR({e.method.expr.member})'
    else:
        #= format_expr(e.method.expr)


def gen_method_isValid(e):
    #[ (pd->headers[${gen_method_hdr_ref(e)}].pointer != NULL)

def gen_method_setInvalid(e):
    #[ pd->headers[${gen_method_hdr_ref(e)}].pointer = NULL

def gen_method_apply(e):
    #[ ${e.method.expr.path.name}_apply(STDPARAMS_IN)

def gen_method_lookahead(e):
    var = generate_var_name('lookahead')
    varh = generate_var_name('lookahead_handle')

    arg0 = e.typeArguments[0]
    size = arg0.size

    if size > 32:
        addError('doing lookahead', f'Lookahead was called on a type that is {size} bits long; maximum supported length is 32')

    #pre[ bitfield_handle_t $varh =
    #pre[ {
    #pre[     .byte_addr   = 0,
    #pre[     .meta        = false,
    #pre[     .bitwidth    = $size,
    #pre[     .bytewidth   = ($size + 7) / 8,
    #pre[     .bitcount    = $size,
    #pre[     .bytecount   = ($size + 7) / 8,
    #pre[     .bitoffset   = 0,
    #pre[     .byteoffset  = 0,
    #pre[     .mask        = 0xffffffff,
    #pre[     .fixed_width = true,
    #pre[ };

    #pre[ ${gen_format_type(arg0, addon=var, use_array=False)} = GET_INT32_AUTO($varh);
    #[ $var

def gen_method_setValid(e):
    hdr = e.method.expr.hdr_ref

    # TODO fix: f must always have an is_vw attribute
    def is_vw(fld):
        if fld.get_attr('is_vw') is None:
            return False
        return f.is_vw

    # TODO is this the max size?
    length = (sum([fld.size if not is_vw(f) else 0 for fld in h.urtype.fields])+7)//8

    #[ pd->headers[${hdr.name}] = (header_descriptor_t) {
    #[     .type = ${hdr.name},
    #[     .length = $length,
    #[     .pointer = calloc(${hdr.urtype.byte_width}, sizeof(uint8_t)),
    #[     /*TODO determine and set this field*/
    #[     .var_width_field_bitwidth = 0,
    #[ };


def gen_fmt_Cast(e, format_as_value=True, expand_parameters=False, needs_variable=False):
    et = e.expr.type
    edt = e.destType
    if (et.node_type, et.size, edt.node_type) == ('Type_Bits', 1, 'Type_Boolean') and not et.isSigned:
        #Cast from bit<1> to bool
        return f"({format_expr(e.expr)})"
    elif (et.node_type, edt.node_type, edt.size) == ('Type_Boolean', 'Type_Bits', 1) and not edt.isSigned:
        #Cast from bool to bit<1>
        return f'({format_expr(e.expr)} ? 1 : 0)'
    elif et.node_type == 'Type_Bits' and edt.node_type == 'Type_Bits':
        if et.isSigned == edt.isSigned:
            if not et.isSigned:                       #Cast from bit<w> to bit<v>
                if et.size > edt.size:
                    return f'({format_type_mask(e.destType)}{format_expr(e.expr)})'
                else:
                    return format_expr(e.expr)
            else:                                              #Cast from int<w> to int<v>
                return f'(({format_type(e.destType)}) {format_expr(e.expr)})'
        elif et.isSigned and not edt.isSigned: #Cast from int<w> to bit<w>
            return f'({format_type_mask(e.destType)}{format_expr(e.expr)})'
        elif not et.isSigned and edt.isSigned: #Cast from bit<w> to int<w>
            if edt.size in {8,16,32}:
                return f'(({format_type(e.destType)}){format_expr(e.expr)})'
            else:
                addError('formatting an expression', f'Cast from bit<{et.size}> to int<{edt.size}> is not supported! (Only int<8>, int<16> and int<32> are supported.)')
                return ''
    #Cast from int to bit<w> and int<w> are performed by P4C
    addError('formatting an expression', f'Cast from {pp_type_16(et)} to {pp_type_16(edt)} is not supported!')
    return ''

def gen_fmt_ComplexOp(e, op, format_as_value=True, expand_parameters=False):
    temp_expr = f'({format_expr(e.left)}{op}{format_expr(e.right)})'
    if e.type.node_type == 'Type_InfInt':
        return temp_expr
    elif e.type.node_type == 'Type_Bits':
        if not e.type.isSigned:
            return f'({format_type_mask(e.type)}{temp_expr})'
        else:
            if e.type.size in {8,16,32}:
                return f'(({format_type(e.type)}){temp_expr})'
            else:
                addError('formatting an expression', f'Expression of type {e.node_type} is not supported on int<{e.type.size}>. (Only int<8>, int<16> and int<32> are supported.)')
                return ''

def get_select_conds(select_expr, case):
    cases_tmp = case.keyset.components if case.keyset.node_type == 'ListExpression' else [case.keyset]

    conds = []
    pres = []
    for k, c in zip(select_expr.select.components, cases_tmp):
        select_type = k.type.node_type
        size = k.type.size #if k.type.node_type == 'Type_Bits' else 0
        case_type = c.node_type

        if case_type == 'DefaultExpression':
            conds.append('true /* default */')
        elif case_type == 'Constant' and select_type == 'Type_Bits' and 32 < size and size % 8 == 0:
            byte_array = int_to_big_endian_byte_array_with_length(c.value, size/8)
            pres.append(f'uint8_t {gen_var_name(c)}[{size/8}] = {byte_array};')
            conds.append(f'memcmp({gen_var_name(k)}, {gen_var_name(c)}, {size / 8}) == 0')
        elif size <= 32:
            if case_type == 'Range':
                conds.append('{0} <= {1} && {1} <= {2}'.format(format_expr(c.left), gen_var_name(k), format_expr(c.right)))
            elif case_type == 'Mask':
                conds.append('({0} & {1}) == ({2} & {1})'.format(format_expr(c.left), format_expr(c.right), gen_var_name(k)))
            else:
                if case_type not in {'Constant'}: #Trusted expressions
                    addWarning('formatting a select case', f'Select statement cases of type {case_type} on {pp_type_16(k.type)} might not work properly.')
                conds.append(f'{gen_var_name(k)} == {format_expr(c)}')
        else:
            addError('formatting a select case', f'Select statement cases of type {case_type} on {pp_type_16(k.type)} is not supported!')
    return ' && '.join(conds), pres

def gen_fmt_SelectExpression(e, format_as_value=True, expand_parameters=False, needs_variable=False):
    #Generate local variables for select values
    for k in e.select.components:
        varname = gen_var_name(k)
        if k.type.node_type == 'Type_Bits' and k.type.size <= 32:
            #pre[ ${format_type(k.type)} $varname = ${format_expr(k)};
        elif k.type.node_type == 'Type_Bits' and k.type.size % 8 == 0:
            #pre[ uint8_t $varname[${k.type.size/8}];
            #pre[ EXTRACT_BYTEBUF_PACKET(pd, ${format_expr(k, False)}, $varname);'
        else:
            addError('formatting select expression', f'Select on type {pp_type_16(k.type)} is not supported!')

    if len(e.selectCases) == 0:
        #[ // found a select expression with no cases, no code to generate
        return

    conds_pres = [get_select_conds(e, case) for idx, case in enumerate(e.selectCases)]

    for _, pres in conds_pres:
        for pre in pres:
            #pre[ ${pre}

    for idx, ((cond, _pre), case) in enumerate(zip(conds_pres, e.selectCases)):
        if idx == 0:
            #{ if (${cond}) { // select case #${idx+1}
        else:
            #[ } else if (${cond}) { // select case #${idx+1}
        #[     parser_state_${case.state.path.name}(STDPARAMS_IN);
    #} }

def gen_fmt_Member(e, format_as_value=True, expand_parameters=False, needs_variable=False):
    if 'hdr_ref' in e:
        # TODO do both individual meta fields and metadata instance fields
        if e.hdr_ref.name == 'metadata':
            #[ pd->fields.FLD(${e.expr.member},${e.member})
        else:
            #[ HDR(${e.expr.member})
    elif e.expr.node_type == 'PathExpression':
        hdr = e.expr.hdr_ref
        if e.expr.urtype.node_type == 'Type_Header':
            #[ (GET_INT32_AUTO_PACKET(pd, HDR(${hdr.name}), FLD(${hdr.name},${e.member})))
        else:
            hdrname = "all_metadatas" if hdr.urtype('is_metadata', False) else hdr.name
            #[ FLD($hdrname, ${e.member})
    else:
        if e.type.node_type in {'Type_Enum', 'Type_Error'}:
            #[ ${e.type.members.get(e.member).c_name}
        elif e.expr('expr', lambda e2: e2.type.name == 'parsed_packet'):
            #[ pd->fields.FLD(${e.expr.member},${e.member})
        else:
            #[ ${format_expr(e.expr)}.${e.member}

###########
# format extern call

def gen_list_elems(elems, last):
    if len(elems) > 0:
        elem0 = elems[0]
        #[ ${elem0}

        for elem in elems[1:]:
            #[ , ${elem}

    #[ ${', ' if len(elems) > 0 else ''}${last}


def gen_format_method_parameter(par):
    if 'expression' in par and 'fld_ref' in par.expression:
        expr = par.expression.expr
        hdrname = expr.member
        fldname = expr.fld_ref.name
        #[ handle(header_desc_ins(pd, HDR($hdrname)), FLD($hdrname, $fldname))
    else:
        #= format_expr(par)

def gen_extern_decl(mname, m):
    mret_type = m.urtype.returnType

    with SugarStyle("inline_comment"):
        ptypes = [format_type(m.type.typeParameters.parameters.get(par.type.path.name).urtype if par.urtype.node_type == 'Type_Name' else par.urtype) for par in m.action_ref.urtype.parameters.parameters]

    #[ extern ${format_type(mret_type)} ${mname}(${gen_list_elems(ptypes, "SHORT_STDPARAMS")});


def gen_format_call_extern(args, mname, m):
    #pre= gen_extern_decl(mname, m)

    with SugarStyle("inline_comment"):
        fmt_args = [fmt_arg for arg in args if not arg.is_vec() for fmt_arg in [gen_format_method_parameter(arg)] if fmt_arg != '']
        #[ ${mname}(${gen_list_elems(fmt_args, "SHORT_STDPARAMS_IN")})

##############

def gen_fmt_MethodCallExpression(e, format_as_value=True, expand_parameters=False, needs_variable=False):
    special_methods = {
        ('Member', 'setValid'):     gen_method_setValid,
        ('Member', 'isValid'):      gen_method_isValid,
        ('Member', 'setInvalid'):   gen_method_setInvalid,
        ('Member', 'apply'):        gen_method_apply,
        ('Member', 'lookahead'):    gen_method_lookahead,
    }

    m = e.method

    if 'member' in m:
        method = special_methods.get((m.node_type, m.member))
        if method is None:
            breakpoint()
        #= method(e)
    elif e.arguments.is_vec() and e.arguments.vec != []:
        mname = m.path.name

        if mname == 'digest':
            #= gen_format_call_digest(e)
        else:
            args = e.arguments
            #= gen_format_call_extern(args, mname, m)
    else:
        if m('expr').type.node_type == 'Type_Extern':
            ee = m.expr
            if m.member in ('lookahead', 'advance', 'length'):
                raise NotImplementedError(f'{ee.type.name}.{m.member} is not supported yet!')

            funname = f"{ee.type.name}_t_{m.member}"
            extern_inst = format_expr(ee)
            extern_type = format_type(ee.urtype.methods.get(m.member, 'Method').urtype.returnType)
            #pre[ extern ${extern_type} ${funname}(${ee.urtype.name}_t);
            #[ $funname($extern_inst)
        else:
            funname = format_expr(m)
            #pre[ extern void ${funname}(SHORT_STDPARAMS);
            #[ $funname(SHORT_STDPARAMS_IN)

def gen_fmt_ListExpression(e, format_as_value=True, expand_parameters=False, needs_variable=False):
    global generated_exprs

    if e.id not in generated_exprs:
        generated_exprs.add(e.id)

        cos = e.components.filterfalse('node_type', 'Constant')

        total_width = '+'.join((f'field_desc(pd, FLD({co.expr.member},{co.fld_ref.name})).bitwidth' for co in cos))

        #pre[ int buffer${e.id}_size = ((${total_width}) +7)/8;
        #pre[ uint8_t buffer${e.id}[buffer${e.id}_size];

        hdrs = unique_everseen(cos.map(lambda co: (co.expr.member, co.hdr_ref)))
        for hdrname, hdr in hdrs:
            field_names = e.components.filter('hdr_ref.name', hdr.name).map('member')
            idxflds = [(idx, fld) for idx, fld in enumerate(hdr.fields) if fld.name in field_names]

            offset = '0'
            while idxflds != []:
                fld0_idx, fld0 = idxflds[0]

                # note: param = (idx, (idxorig, fld))
                lam = lambda param: param[1][0] == fld0_idx + param[0]

                neighbour_flds = list(takewhile(lam, enumerate(idxflds)))
                width = '+'.join((f'field_desc(pd, FLD({hdrname},{fld.name})).bitwidth' for _, (_, fld) in neighbour_flds))
                #pre[ memcpy(buffer${e.id} + (${offset}+7)/8, field_desc(pd, FLD(${hdrname}, ${fld0.name})).byte_addr, ((${width}) +7)/8);

                idxflds = idxflds[len(neighbour_flds):]
                offset += f'+{width}'

    #[ (uint8_buffer_t) { .buffer = buffer${e.id}, .buffer_size = buffer${e.id}_size } /* ListExpression */

def gen_fmt_StructInitializerExpression(e, format_as_value=True, expand_parameters=False, needs_variable=False):
    #{ (${gen_format_type(e.type)}) {
    for component in e.components:
        tref = component.expression.expr("ref.urtype")
        if tref and tref.is_metadata:
            #[ .${component.name} = (GET_INT32_AUTO_PACKET(pd, HDR(all_metadatas), FLD(${tref.name},${component.expression.member}))),
        else:
            if component.expression.type.size <= 32:
                #[ .${component.name} = ${gen_format_expr(component.expression)},
            else:
                #[ /* ${component.name}/${component.expression.type.size}b will be initialised afterwards */
    #} }

def gen_fmt_StructExpression(e, format_as_value=True, expand_parameters=False, needs_variable=False):
    varname = gen_var_name(e)
    #pre[ ${format_type(e.type)} $varname;
    for component in e.components:
        tref = component.expression.expr("ref.urtype")
        if tref and tref.is_metadata:
            #pre[ $varname.${component.name} = (GET_INT32_AUTO_PACKET(pd, HDR(all_metadatas), FLD(${tref.name},${component.expression.member})));
        else:
            if component.expression.type.size <= 32:
                #pre[ $varname.${component.name} = ${gen_format_expr(component.expression)};
            else:
                bitsize = (component.expression.type.size+7)//8
                hdrinst = component.expression.expr.hdr_ref.name
                fldinst = component.expression.member
                #pre[ EXTRACT_BYTEBUF_PACKET(pd, HDR($hdrinst), FLD(${hdrinst},$fldinst), &($varname.${component.name}));
    #[ $varname


def gen_fmt_Constant(e, format_as_value=True, expand_parameters=False, needs_variable=False):
    if e.type.node_type == 'Type_Bits':
        if e.type.size > 32 or needs_variable:
            name, hex_content = make_const(e)
            const_var = generate_var_name(f"const{e.type.size}_", name)

            #pre[ uint8_t ${const_var}[] = {$hex_content};
            #[ ${const_var}
        else:
            is_not_too_big = e.type.size <= 4 or e.value < 2**(e.type.size-1)
            value_hint = "" if is_not_too_big else f" /* probably -{2**e.type.size - e.value} */"
            #[ ${with_base(e.value, e.base)}${value_hint}
    else:
        #[ ${e.value}


def gen_fmt_Operator(e, nt, format_as_value=True, expand_parameters=False):
    unary_ops = ('Neg', 'Cmpl', 'LNot')
    if nt in unary_ops:
        expr = format_expr(e.expr)
        if nt == 'Neg':
            if e.type.node_type == 'Type_Bits' and not e.type.isSigned:
                #[ (${format_type_mask(e.type)}(${2**e.type.size}-${expr}))
            else:
                #[ (-${expr})
        elif nt == 'Cmpl':
            #[ (${format_type_mask(e.type)}(~${expr}))
        elif nt == 'LNot':
            #[ (!${expr})
    else:
        left = format_expr(e.left)
        right = format_expr(e.right)
        size = e.left.type.size
        if nt in simple_binary_ops:
            if nt == 'Equ' and size > 32:
                #[ 0 == memcmp($left, $right, (${size} + 7) / 8)
            else:
                op = simple_binary_ops[nt]
                #[ (($left) ${op} ($right))
        elif nt == 'Sub' and e.type.node_type == 'Type_Bits' and not e.type.isSigned:
            #Subtraction on unsigned values is performed by adding the negation of the second operand
            #[ (${format_type_mask(e.type)}($left + (${2 ** e.type.size}-$right)))
        elif nt == 'Shr' and e.type.node_type == 'Type_Bits' and e.type.isSigned:
            #Right shift on signed values is performed with a shift width check
            #[ ((${right}>${size}) ? 0 : (${left} >> ${right}))
        else:
            #These formatting rules MUST follow the previous special cases
            #= gen_fmt_ComplexOp(e, complex_binary_ops[nt], format_as_value, expand_parameters)


def funs_with_cond(name_cond):
    return ((name, fun) for name, fun in getmembers(sys.modules[__name__], isfunction) if name_cond(name))

def gen_format_expr(e, format_as_value=True, expand_parameters=False, needs_variable=False):
    prefix = 'gen_fmt_'
    complex_cases = {name[len(prefix):]: fun for name, fun in funs_with_cond(lambda name: name.startswith(prefix))}

    if e is None:
        addError("Formatting expression", "An expression was found to be None, this should be impossible")
        return "FORMAT_EXPR(None)"

    nt = e.node_type

    if nt == 'Member' and 'fld_ref' in e:
        fldname = e.fld_ref.name
        # note: this special case is here because it uses #pre; it should be in 'gen_fmt_Member'
        if not format_as_value:
            #[ FLD(${e.expr.hdr_ref.name}, ${fldname})
        elif e.type.size > 32 or needs_variable:
            var_name = generate_var_name(f"hdr_{e.expr.hdr_ref.name}_{fldname}")
            byte_size = (e.type.size + 7) // 8

            hdrname = e.expr.member

            #pre[ uint8_t* ${var_name}[${byte_size}];
            #pre[ EXTRACT_BYTEBUF_PACKET(pd, HDR(${hdrname}), FLD(${hdrname},${fldname}), ${var_name});

            #= var_name
        else:
            hdrname = 'all_metadatas' if e.expr.hdr_ref.urtype.is_metadata else e.expr.member
            #[ (GET_INT32_AUTO_PACKET(pd, HDR(${hdrname}), FLD(${hdrname},${fldname})))
    elif nt in complex_cases:
        case = complex_cases[nt]
        if nt == 'SelectExpression':
            with SugarStyle('line_comment'):
                #= case(e, format_as_value, expand_parameters, needs_variable)
        else:
            #= case(e, format_as_value, expand_parameters, needs_variable)
    elif nt in simple_binary_ops or nt in complex_binary_ops or nt in ('Neg', 'Cmpl', 'LNot'):
        #= gen_fmt_Operator(e, nt, format_as_value, expand_parameters)

    elif nt == 'DefaultExpression':
        #[ default
    elif nt == 'Parameter':
        #[ ${format_type(e.type)} ${e.name}
    elif nt == 'BoolLiteral':
        if e.value:
            #[ true
        else:
            #[ false
    elif nt == 'StringLiteral':
        #[ "${e.value}"
    elif nt == 'TypeNameExpression':
        #= format_expr(e.typeName.type_ref)
    elif nt == 'Mux':
        #[ (${format_expr(e.e0)} ? ${format_expr(e.e1)} : ${format_expr(e.e2)})
    elif nt == 'Slice':
        retsize = e.type.size
        origsize = e.e0.type.size
        mask = format_type_mask(e.type)
        e0 = format_expr(e.e0)
        e2 = format_expr(e.e2)
        if retsize <= 32:
            if origsize <= 32:
                #[ ($mask(${e0} >> ${e2}))
            elif retsize % 8 == 0 and origsize % 8 == 0:
                #[ (${format_type(e.type)})(*(&($e0) + ($e2/8)))
            else:
                addError('formatting >> operator', f'Unsupported slice: source or destination is not multibyte size)')
        else:
            addError('formatting >> operator', f'Unsupported slice: result is bigger than 32 bits ({size} bits)')
    elif nt == 'Concat':
        #[ ((${format_expr(e.left)} << ${e.right.type.size}) | ${format_expr(e.right)})
    elif nt == 'PathExpression':
        name = e.path.name
        is_local = is_control_local_var(name)
        is_abs = expand_parameters and not e.path.absolute
        is_param = "decl_ref" in e and e.decl_ref.node_type == 'Parameter'
        is_action = "action_ref" in e
        if is_local:
            #[ local_vars->${name}
        elif is_abs or is_param:
            #[ parameters->${name}
        elif is_action:
            #[ ${e.action_ref.name}
        else:
            #[ ${name}
    elif nt == 'Argument':
        #= format_expr(e.expression)
    else:
        addError("formatting an expression", f"Expression {e} of type {nt} is not supported yet!")


################################################################################

method_call_envs = {}

def get_method_call_env(mcall, mname):
    global method_call_envs

    method = mcall.method.type

    # TODO maybe types other than Type_Enum will have to be included as well
    type_env_raw = {par.name: arg for par, arg in zip(method.typeParameters.parameters, mcall.typeArguments)}
    type_env_raw |= {par.type.name: par.type for par in method.parameters.parameters if par.type.node_type == 'Type_Enum' and par.type.name not in type_env_raw}

    type_env = {parname: format_type(type_env_raw[parname]) for parname in type_env_raw}

    if mname in method_call_envs and type_env != method_call_envs[mname]:
        addError("determining method call type args", f"Method {mname} is called {len(calls)} times with at least two different sets of argument types")

    return type_env


def fld_infos(e):
    for fld in e.arguments[1].expression.components:
        fe = fld.expression
        fee = fe.expr
        if 'hdr_ref' not in fee or fee.hdr_ref.urtype.is_metadata:
            hdrname = fee.hdr_ref.name
        else:
            hdrname = fee.member
        yield hdrname, fe.member, fe.urtype.size


def gen_format_call_digest(e):
    var = generate_var_name('digest')
    name = e.typeArguments['Type_Name'][0].path.name
    receiver = e.arguments[0].expression.value

    #pre[ #ifdef T4P4S_NO_CONTROL_PLANE
    #pre[ #error "Generating digest when T4P4S_NO_CONTROL_PLANE is defined"
    #pre[ #endif

    #pre[ debug("    " T4LIT(<,outgoing) " " T4LIT(Sending digest,outgoing) " to port " T4LIT(%d,port) "\n", ${e.arguments[0].expression.value});
    for hdrname, fldname, size in fld_infos(e):
        #pre[ dbg_bytes(field_desc(pd, FLD(${hdrname},${fldname})).byte_addr, (${size}+7)/8, "        : "T4LIT(${fldname},field)"/"T4LIT(${size})" = ");

    #pre[ ctrl_plane_digest $var = create_digest(bg, "$name");
    for hdrname, fldname, size in fld_infos(e):
        #pre[ add_digest_field($var, field_desc(pd, FLD(${hdrname},${fldname})).byte_addr, $size);

    #[ send_digest(bg, $var, $receiver);
    #[ sleep_millis(DIGEST_SLEEP_MILLIS);

################################################################################

def format_declaration(d, varname_override = None):
    with SugarStyle("no_comment"):
        return gen_format_declaration(d, varname_override)

# TODO use the varname argument in all cases where a variable declaration is created
def format_type(t, varname = None, resolve_names = True, addon = ""):
    with SugarStyle("inline_comment"):
        # use_array = varname is not None and 'size' in t.urtype and t.urtype.size > 32
        use_array = varname is not None
        result = gen_format_type(t, resolve_names, use_array=use_array, addon=addon).strip()

    if varname is None:
        return result

    split = result.split(" ")
    essential_part = 2 if split[0] in ['enum', 'struct'] else 1

    type1 = " ".join(split[0:essential_part])
    type2 = " ".join(split[essential_part:])
    return f"{type1} {varname}{type2}"

def format_expr(e, format_as_value=True, expand_parameters=False, needs_variable=False):
    with SugarStyle("inline_comment"):
        return gen_format_expr(e, format_as_value, expand_parameters, needs_variable)

def format_statement(stmt, ctl=None):
    if ctl is not None:
        compiler_common.enclosing_control = ctl

    ret = gen_format_statement(stmt)

    buf1 = compiler_common.pre_statement_buffer
    buf2 = compiler_common.post_statement_buffer
    compiler_common.pre_statement_buffer = ""
    compiler_common.post_statement_buffer = ""
    return f'{buf1}{ret}{buf2}'


def format_type_mask(t):
    with SugarStyle("inline_comment"):
        return gen_format_type_mask(t)

def gen_var_name(item, prefix = None):
    if not prefix:
        prefix = f"value_{item.node_type}"
    #[ ${prefix}_${item.id}
