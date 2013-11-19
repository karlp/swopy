stlinkv2_proto = Proto("stlinkv2", "STLink/V2 api")

local top_funcs = {
	[0xf1] = "GET VERSION",
	[0xf2] = "DEBUG COMMAND",
	[0xf3] = "DFU COMMAND",
	[0xf4] = "SWIM COMMAND",
	[0xf5] = "GET MODE",
	[0xf7] = "GET VOLTAGE"
}

local debug_command_funcs = {
	[0x7] = "READMEM32",
	[0x8] = "WRITEMEM32",
        [0x21] = "Exit Debug",
	[0x30] = "ENTER",
	[0x33] = "READ REG",
	[0x34] = "WRITE REG",
	[0x35] = "WRITE DEBUG REG",
	[0x36] = "READ DEBUG REG",
        [0x3a] = "Read all registers",
	[0x3e] = "UNKNOWN MAGIC SYNC",
	[0x40] = "Start Trace",
	[0x41] = "Stop Trace",
	[0x42] = "Get Trace Count"
}

local command_enter_funcs = {
    [0x00] = "Enter JTAG",
    [0xa3] = "Enter SWD"
}

local response_codes = {
    [0x80] = "OK"
}

local f = stlinkv2_proto.fields
f.f_tfunc = ProtoField.uint8("stlinkv2.function", "Function", base.HEX, top_funcs)
f.f_dfunc = ProtoField.uint8("stlinkv2.debug.command", "Debug Command", base.HEX, debug_command_funcs)
f.f_dsubfunc = ProtoField.uint8("stlinkv2.debug.subcommand", "Debug subcommand", base.HEX, command_enter_funcs)
f.f_addr = ProtoField.uint32("stlinkv2.addr", "Address", base.HEX)
f.f_value = ProtoField.uint32("stlinkv2.value", "Value", base.HEX)
f.f_length = ProtoField.uint16("stlinkv2.length", "Length", base.DEC)
f.f_unknown = ProtoField.uint16("stlinkv2.unknown", "unknown", base.HEX)
f.f_data = ProtoField.bytes("stlinkv2.data", "data")
f.f_response_status = ProtoField.uint16("stlinkv2.response.status", "status", base.HEX, response_codes)
f.f_trace_count = ProtoField.uint16("stlinkv2.trace.count", "available", base.DEC)
f.f_trace_buff = ProtoField.uint16("stlinkv2.trace.buffsize", "buffsize", base.DEC)
f.f_trace_hz = ProtoField.uint32("stlinkv2.trace.hz", "trace speed (hz)", base.DEC)

local f_usb_ep_num = Field.new("usb.endpoint_number.endpoint")

local function getstring(fi)
    local ok, val = pcall(tostring, fi)
    if not ok then val = "(unknown)" end
    return val
end

-- write32 doesn't have a response on the in endpoint, it tweaks decoding on the _out_ endpoint
local responses = {
    NOTSET = 1, READMEM32 = 2, GENERIC = 3, READDEBUG = 4,
    WRITEMEM32 = 5,
    TRACECOUNT = 6
}
    
local expected = responses.NOTSET

function stlinkv2_proto.dissector(buffer, pinfo, tree)
	pinfo.cols["protocol"] = "STLinkv2"

        --[[
        -- This was very helpful for working out the field names I could use with Field.new()
        local fields = { all_field_infos() }
        for ix, finfo in ipairs(fields) do
            print(string.format("ix=%d, finfo.name = %s, finfo.value=%s", ix, finfo.name, getstring(finfo)))
        end
        ]]--

	-- create protocol tree
	local t_stlinkv2 = tree:add(stlinkv2_proto, buffer())
	local offset = 0

        local function response_header(res)
            t_stlinkv2:add_le(f.f_response_status, res)
            -- TODO - this should use the response_codes map I think?!
            if res:le_uint() == 0x80 then
                pinfo.cols["info"]:append(" OK")
            else
                pinfo.cols["info"]:append(" unknown?!" .. res.le_uint())
            end
        end

        -- response data on general IN endpoint
	local ep = f_usb_ep_num()
        if (ep.value == 1) then
                pinfo.cols["info"] = "Response"
                if expected == responses.GENERIC then
                    local res = buffer(offset, 2)
                    offset = offset + 2
                    response_header(res)
                elseif expected == responses.READDEBUG then
                    local res = buffer(offset, 2)
                    response_header(res)
                    t_stlinkv2:add_le(f.f_unknown, buffer(offset + 2, 2))
                    local val = buffer(offset + 4, 4)
                    t_stlinkv2:add_le(f.f_value, val)
                    pinfo.cols["info"]:append(string.format(" ==> %#010x", val:le_uint()))
                    offset = offset + 8
                elseif expected == responses.READMEM32 then
                    -- FIXME - we only handle decoding single word reads :(
                    -- would need to save the count from the request?
                    local val = buffer(offset, 4)
                    t_stlinkv2:add_le(f.f_value, val)
                    offset = offset + 4
                    pinfo.cols["info"]:append(string.format(" ==> %#010x", val:le_uint()))
                elseif expected == responses.TRACECOUNT then
                    local val = buffer(offset, 2)
                    t_stlinkv2:add_le(f.f_trace_count, val)
                    val = val:le_uint()
                    offset = offset + 2
                    pinfo.cols["info"]:append(string.format(" ==> %d (%#x) bytes", val, val))
                else
	            t_stlinkv2:add(f.f_data, buffer(offset))
                end
                expected = nil
		return
	end

        -- swo input data
        if (ep.value == 3) then
            pinfo.cols["info"] = "SWO/SWV data output"
	    t_stlinkv2:add(f.f_data, buffer(offset))
            return
        end

        if (expected == responses.WRITEMEM32) then
            assert(ep.value == 2)
            -- FIXME - only works for single word writes!
            local value = buffer(offset, 4)
            t_stlinkv2:add_le(f.f_value, value)
            value = value:le_uint()
            pinfo.cols["info"]= string.format("Write out ==> %d (%#010x)", value, value)
            expected = nil
            return
        end

	local func_code = buffer(offset, 1)
	t_stlinkv2:add(f.f_tfunc, func_code)
        func_code = func_code:uint()
	offset = offset + 1
	-- set info column to function name
	pinfo.cols["info"] = top_funcs[func_code]

	if func_code == 0xf2 then
		tfunc = buffer(offset, 1)
		t_stlinkv2:add(f.f_dfunc, tfunc)
                tfunc = tfunc:uint()
		pinfo.cols["info"]:append(" - " .. tostring(debug_command_funcs[tfunc]))
		offset = offset + 1
		if tfunc == 0x35 then -- write debug reg
                        local addr = buffer(offset, 4)
                        local value = buffer(offset + 4, 4)
			t_stlinkv2:add_le(f.f_addr, addr)
			t_stlinkv2:add_le(f.f_value, value)
                        local extra = string.format(" %#010x => %d (%#010x)", addr:le_uint(), value:le_uint(), value:le_uint())
                        pinfo.cols["info"]:append(extra)
                        expected = responses.GENERIC
                        offset = offset + 8
		elseif tfunc ==  0x36 then -- read debug reg
                        local addr = buffer(offset, 4)
			t_stlinkv2:add_le(f.f_addr, addr)
                        pinfo.cols["info"]:append(string.format(" %#010x", addr:le_uint()))
			offset = offset + 4
                        expected = responses.READDEBUG
		elseif tfunc == 0x07 then -- readmem32
                        local addr = buffer(offset, 4)
                        local length = buffer(offset + 4, 2)
			t_stlinkv2:add_le(f.f_addr, addr)
			t_stlinkv2:add_le(f.f_length, length)
                        pinfo.cols["info"]:append(string.format(" %#010x @ %d", addr:le_uint(), length:le_uint()))
			offset = offset + 6
                        expected = responses.READMEM32
		elseif tfunc == 0x08 then -- writemem32
                        local addr = buffer(offset, 4)
                        local length = buffer(offset + 4, 2)
			t_stlinkv2:add_le(f.f_addr, addr)
			t_stlinkv2:add_le(f.f_length, length)
                        pinfo.cols["info"]:append(string.format(" %#010x @ %d", addr:le_uint(), length:le_uint()))
			offset = offset + 6
                        expected = responses.WRITEMEM32
                elseif tfunc == 0x40 then -- start trace
                        local buffsize = buffer(offset, 2)
                        local hz = buffer(offset + 2, 4)
                        t_stlinkv2:add_le(f.f_trace_buff, buffsize)
                        t_stlinkv2:add_le(f.f_trace_hz, hz)
                        offset = offset + 6
                        expected = responses.GENERIC
                elseif tfunc == 0x41 then -- stoptrace
                        expected = responses.GENERIC
                elseif tfunc == 0x42 then -- get trace count
                        expected = responses.TRACECOUNT
                elseif tfunc == 0x30 then -- enter subcommand
		        subfunc = buffer(offset, 1)
		        t_stlinkv2:add(f.f_dsubfunc, subfunc)
                        expected = responses.GENERIC
                        offset = offset + 1
                else
                        expected = nil
		end
			
	end
	t_stlinkv2:add(f.f_data, buffer(offset))
end

usb_table = DissectorTable.get("usb.bulk")
-- this is the vendor specific class, which is how the usb.bulk table is arranged.
usb_table:add(0xff, stlinkv2_proto)
-- this is the unknown class, which seems to happen with oocd?!
usb_table:add(0xffff, stlinkv2_proto)
