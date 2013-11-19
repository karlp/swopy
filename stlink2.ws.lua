stlinkv2_proto = Proto("stlinkv2", "STLink/V2 api (lua)")

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
	[0xa3] = "ENTER SWD",
	[0x33] = "READ REG",
	[0x34] = "WRITE REG",
	[0x35] = "WRITE DEBUG REG",
	[0x36] = "READ DEBUG REG",
	[0x3e] = "UNKNOWN MAGIC SYNC",
	[0x40] = "Start Trace",
	[0x41] = "Stop Trace",
	[0x42] = "Get Trace Count"
}

local response_codes = {
    [0x80] = "OK"
}

local f = stlinkv2_proto.fields
f.f_tfunc = ProtoField.uint8("stlinkv2.tfunc", "Function", base.HEX, top_funcs)
f.f_dfunc = ProtoField.uint8("stlinkv2.dcmd", "Debug Command", base.HEX, debug_command_funcs)
f.f_addr = ProtoField.uint32("stlinkv2.addr", "Address", base.HEX)
f.f_value = ProtoField.uint32("stlinkv2.value", "Value", base.HEX)
f.f_length = ProtoField.uint16("stlinkv2.length", "Length", base.DEC)
f.f_data = ProtoField.bytes("stlinkv2.data", "data")
f.f_response_status = ProtoField.uint16("stlinkv2.response.status", "status", base.HEX, response_codes)

local f_usb_ep_num = Field.new("usb.endpoint_number.endpoint")

local function getstring(fi)
    local ok, val = pcall(tostring, fi)
    if not ok then val = "(unknown)" end
    return val
end

-- write32 doesn't have a response on the in endpoint, it tweaks decoding on the _out_ endpoint
local responses = {
    NOTSET = 1, READMEM32 = 2, WRITEDEBUG = 3, READDEBUG = 4,
    WRITEMEM32 = 5 }
    
local expected = responses.NOTSET

function stlinkv2_proto.dissector(buffer, pinfo, tree)
	pinfo.cols["protocol"] = "STLinkv2"

        local fields = { all_field_infos() }
        for ix, finfo in ipairs(fields) do
            print(string.format("ix=%d, finfo.name = %s, finfo.value=%s", ix, finfo.name, getstring(finfo)))
        end

	-- create protocol tree
	local t_stlinkv2 = tree:add(stlinkv2_proto, buffer())
	local offset = 0

        -- response data on general IN endpoint
	local ep = f_usb_ep_num()
        if (ep.value == 1) then
                pinfo.cols["info"] = "Response"
                if expected == responses.WRITEDEBUG then
                    t_stlinkv2:add_le(f.f_response_status, buffer(offset, 2))
                    offset = offset + 2
                    pinfo.cols["info"]:append(" OK")
                elseif expected == responses.READMEM32 then
                    -- FIXME - we only handle decoding single word reads :(
                    -- would need to save the count from the request?
                    t_stlinkv2:add_le(f.f_value, buffer(offset, 4))
                    offset = offset + 4
                else
	            t_stlinkv2:add(f.f_data, buffer(offset))
                end
		return
	end

        -- swo input data
        if (ep.value == 3) then
            pinfo.cols["info"] = "SWO/SWV data output"
	    t_stlinkv2:add(f.f_data, buffer(offset))
            return
        end

--[[
        print ("expected is: " .. tostring(expected))
        print ("responses.WRITEMEM32 is " .. tostring(responses.WRITEMEM32))
        if (expected == responses.WRITEMEM32) then
            assert(ep.value == 2)
            -- FIXME - only works for single word writes!
            local value = buffer(offset, 4):le_uint()
            t_stlinkv2:add(f.value, value)
            pinfo.cols["info"]:append(" Writemem32 data out")
            return
        end
]]--

	local func_code = buffer(offset, 1)
        expected = responses.NOTSET
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
                        local extra = string.format(" %#x => %d (%#x)", addr:le_uint(), value:le_uint(), value:le_uint())
                        pinfo.cols["info"]:append(extra)
                        expected = responses.WRITEDEBUG
                        offset = offset + 8
		elseif tfunc ==  0x36 then -- read debug reg
                        local addr = buffer(offset, 4)
			t_stlinkv2:add_le(f.f_addr, addr)
                        pinfo.cols["info"]:append(string.format(" %#x", addr:le_uint()))
			offset = offset + 4
                        expected = responses.READDEBUG
		elseif tfunc == 0x07 then -- readmem32
                        local addr = buffer(offset, 4):le_uint()
                        local length = buffer(offset + 4, 2):le_uint()
			t_stlinkv2:add(f.f_addr, addr)
			t_stlinkv2:add(f.f_length, length)
                        pinfo.cols["info"]:append(string.format(" %#x @ %d", addr, length))
			offset = offset + 6
                        expected = responses.READMEM32
		elseif tfunc == 0x08 then -- writemem32
                        local addr = buffer(offset, 4):le_uint()
                        local length = buffer(offset + 4, 2):le_uint()
			t_stlinkv2:add(f.f_addr, addr)
			t_stlinkv2:add(f.f_length, length)
                        pinfo.cols["info"]:append(string.format(" %#x @ %d", addr, length))
			offset = offset + 6
                        expected = responses.WRITEMEM32
		end
			
	end
	t_stlinkv2:add(f.f_data, buffer(offset))
end

usb_table = DissectorTable.get("usb.bulk")
usb_table:add(0xff, stlinkv2_proto)
