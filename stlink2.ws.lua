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

local f = stlinkv2_proto.fields
f.f_tfunc = ProtoField.uint8("stlinkv2.tfunc", "Function", base.HEX, top_funcs)
f.f_dfunc = ProtoField.uint8("stlinkv2.dcmd", "Debug Command", base.HEX, debug_command_funcs)
f.f_addr = ProtoField.uint32("stlinkv2.addr", "Address", base.HEX)
f.f_value = ProtoField.uint32("stlinkv2.value", "Value", base.HEX)
f.f_length = ProtoField.uint16("stlinkv2.length", "Length", base.DEC)
f.f_data = ProtoField.bytes("stlinkv2.data", "data")


function stlinkv2_proto.dissector(buffer, pinfo, tree)
	pinfo.cols["protocol"] = "STLinkv2"

	-- don't try and decode inbound packets like this.
	-- this doesn't work either :(
	print(pinfo.dst)
	if pinfo.dst == "host" then
		return
	end

	-- create protocol tree
	local t_stlinkv2 = tree:add(stlinkv2_proto, buffer())
	local offset = 0

	local func_code = buffer(offset, 1):uint()
	t_stlinkv2:add(f.f_tfunc, func_code)
	offset = offset + 1
	-- set info column to function name
	pinfo.cols["info"] = top_funcs[func_code]

	if func_code == 0xf2 then
		tfunc = buffer(offset, 1):uint()
		t_stlinkv2:add(f.f_dfunc, tfunc)
		pinfo.cols["info"]:append(" - " .. debug_command_funcs[tfunc])
		offset = offset + 1
		if tfunc == 0x35 then -- write debug reg
			t_stlinkv2:add_le(f.f_addr, buffer(offset, 4))
			t_stlinkv2:add_le(f.f_value, buffer(offset + 4, 4))
			offset = offset + 8
		elseif tfunc ==  0x36 then -- read debug reg
			t_stlinkv2:add_le(f.f_addr, buffer(offset, 4))
			offset = offset + 4
		elseif tfunc == 0x07 then -- readmem32
			t_stlinkv2:add_le(f.f_addr, buffer(offset, 4))
			t_stlinkv2:add_le(f.f_length, buffer(offset + 4, 2))
			offset = offset + 6
		elseif tfunc == 0x08 then -- writemem32
			t_stlinkv2:add_le(f.f_addr, buffer(offset, 4))
			t_stlinkv2:add_le(f.f_length, buffer(offset + 4, 2))
			offset = offset + 6
			-- need to flag that the next write is the values...
		end
			
	end
	t_stlinkv2:add(f.f_data, buffer(offset))
end

usb_table = DissectorTable.get("usb.bulk")
usb_table:add(0xff, stlinkv2_proto)
