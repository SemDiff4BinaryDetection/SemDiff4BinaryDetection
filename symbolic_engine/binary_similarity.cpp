//#define USE_STANDARD_FILE_FUNCTIONS
#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <search.hpp>
#include <ua.hpp>
#include <xref.hpp>
#include <typeinf.hpp>
#include "Headers/value_calculate/x64_update.h"
#include "Headers/value_calculate/x64_mylibrary.h"
#include "Headers/IR/x64_IR.h"
#include "Headers/cross_arch_preprocessor/x64_preprocessor.h"
#include "Headers/cross_arch_preprocessor/ARM_preprocessor.h"
#include "Headers/cross_arch_preprocessor/MIPS_proprecessor.h"
#include <sys/stat.h>
int OURPUT_NUM=1;
//--------------------------------------------------------------------------
struct plugin_ctx_t : public plugmod_t
{
  virtual bool idaapi run(size_t) override;
  bool symbolically_execute_single_function();
  bool symbolically_execute_all_functions();
  void symbolically_execute_each_functions(int n,std::string this_binary_path);
  bool has_already_processed_function(int n, std::string this_binary_path);
};





//--------------------------------------------------------------------------
bool idaapi plugin_ctx_t::run(size_t)
{
	
	//bool result = symbolically_execute_single_function();
	//return result;
	symbolically_execute_all_functions();
	return true;
}

bool idaapi plugin_ctx_t:: symbolically_execute_single_function()
{
	ea_t end, start, ea1;
	msg("startu\n");
	warning("processor type is: %d", ph.id);
	ea_t ea = get_screen_ea();
	func_t* func = get_func(ea);
	qstring function_name;
	get_func_name(&function_name, ea);
	std::string working_path = "C:\\Program Files\\IDA Pro 7.5 SP3\\IDA SDK and Tools\\idasdk75\\plugins\\semdiff\\semdiff\\symbolic_engine\\x64\\Debug\\";
	if (ph.id == 0)
		working_path = working_path + "x64_" + function_name.c_str();
	else if (ph.id == 13)
		working_path = working_path + "ARM_" + function_name.c_str();

	mkdir(working_path.c_str());//Make the folder for current function.
	initialize_global_variable();
	init_conditional_jump_map();
	if (ph.id == 0)
	{
		check_windows_or_linux();
		init_x64_my_instruction(func);
		x64_print_IR_file(working_path, func);
		//x64_init_iterator_var();
		init_x64_my_insn_IR(func);
		init_recalculated_yet_map();
		x64_random_infer_this_insn_propagate_next(func, func->start_ea);
		//init_IR_reserve_insns(func);
		//x64_translate_return_value(ea, func);
		x64_translate_all_insn(func);
		//x64_display_translate_result(func);
		//x64_display_results(func);
		//x64_analyze_conditional_jump(func);
		//print_conditional_jump(working_path);
		x64_print_to_file(ea, working_path, func);
		//x64_clear_all();
	}
	//else if (ph.id == 12)
		//MIPS_infer_this_insn_propagate_next(func, func->start_ea);
	else if (ph.id == 13)
	{
		ARM_init_ARM_my_instruction(func);
		ARM_print_IR_file(working_path, func);
		for (int i = 0;i < OURPUT_NUM;i++)
		{
			//ARM_init_iterator_var();
			init_ARM_my_insn_IR(func);
			init_recalculated_yet_map();
			ARM_random_infer_this_insn_propagate_next(func, func->start_ea);
			//ARM_translate_return_value(ea, func);
			ARM_translate_each_insn(func);
			ARM_delete_all_hash_tag(func);
			//ARM_display_translate_result(func);
			//ARM_analyze_conditional_jump(func);
			//print_conditional_jump(working_path);
			ARM_print_to_file(ea, working_path, func);
			//x64_clear_all();
		}
	}


	//display_results(func);
	//display_translate_result(func);
	return true;
}

bool idaapi plugin_ctx_t::symbolically_execute_all_functions()//symbolically execute all functions in binary in order.
{
	msg("start\n");
	warning("processor type is: %d", ph.id);
	check_windows_or_linux();
	int total_functions= get_func_qty();
	std::string time_out_functions;
	std::string working_path = "C:\\Program Files\\IDA Pro 7.5 SP3\\IDA SDK and Tools\\idasdk75\\plugins\\semdiff\\semdiff\\symbolic_engine\\x64\\Debug\\";
	char binary_name[150];
	get_root_filename(binary_name, 150);
	std::string this_binary_path = working_path;
	this_binary_path+=binary_name;
	mkdir(this_binary_path.c_str());//Make the folder for this binary.
	std::string timeout_report = working_path + "time_out_functions.txt";
	for (int n = 0;n < total_functions;n++)
	{
		if (has_already_processed_function(n, this_binary_path))
			continue;
		symbolically_execute_each_functions(n, this_binary_path);
	}

	print_uncalcuulateble_functions(this_binary_path);
	//display_results(func);
	//display_translate_result(func);
	return true;
}

bool idaapi plugin_ctx_t::has_already_processed_function(int n, std::string this_binary_path)
{
	func_t* func = getn_func(n);
	ea_t ea = func->start_ea;
	qstring function_name;
	get_func_name(&function_name, ea);
	std::string one_function_path;
	one_function_path = this_binary_path + "\\x64_" + function_name.c_str();
	struct stat sb;
	if (stat(one_function_path.c_str(), &sb) != 0)
		//warning("cannot access %s\n", one_function_path.c_str());
		return false;
	else if (sb.st_mode & S_IFDIR)  // S_ISDIR() doesn't exist on my windows 
		//warning("%s is a directory\n", one_function_path.c_str());
		return true;
	else
		//warning("%s is no directory\n", one_function_path.c_str());
		return false;
	
}

void idaapi plugin_ctx_t::symbolically_execute_each_functions(int n,std::string this_binary_path)
{
	
	// msg("getting next function \n");
	func_t* func = getn_func(n);
	ea_t ea = func->start_ea;
	qstring function_name;
	get_func_name(&function_name, ea);
	std::string msg_to_show = "processing: ";
	msg_to_show = msg_to_show + function_name.c_str();
	msg(msg_to_show.c_str());
	std::string one_function_path;
	if (ph.id == 0)
		one_function_path = this_binary_path + "\\x64_" + function_name.c_str();
	else if (ph.id == 13)
		one_function_path = this_binary_path + "\\ARM_" + function_name.c_str();
	mkdir(one_function_path.c_str());//Make the folder for current function.
	initialize_global_variable();
	init_conditional_jump_map();
	if (ph.id == 0)
	{
		init_x64_my_instruction(func);
		x64_print_IR_file(one_function_path, func);
		for (int i = 0;i < OURPUT_NUM;i++)
		{
			//x64_init_iterator_var();
			init_x64_my_insn_IR(func);
			init_recalculated_yet_map();
			x64_random_infer_this_insn_propagate_next(func, func->start_ea);
			//std::future<void> fut = std::async(std::launch::async, );//execute thread with timeout
			std::string function_name_string = "processing ";
			function_name_string += function_name.c_str();
			msg(function_name_string.c_str());
			//std::future_status status = fut.wait_for(std::chrono::seconds(5));
			//while (status != std::future_status::ready)
				;

			
			//init_IR_reserve_insns(func);
			//x64_translate_return_value(ea, func);
			x64_translate_all_insn(func);
			//x64_display_translate_result(func);
			//x64_display_results(func);
			//x64_analyze_conditional_jump(func);
			//print_conditional_jump(working_path);
 			x64_print_to_file(ea, one_function_path, func);
			//x64_clear_all();
		}
	}
	//else if (ph.id == 12)
		//MIPS_infer_this_insn_propagate_next(func, func->start_ea);
	else if (ph.id == 13)
	{
		ARM_init_ARM_my_instruction(func);
		ARM_print_IR_file(one_function_path, func);
		for (int i = 0;i < OURPUT_NUM;i++)
		{
			//ARM_init_iterator_var();
			init_ARM_my_insn_IR(func);
			init_recalculated_yet_map();
			ARM_random_infer_this_insn_propagate_next(func, func->start_ea);
			//std::future<void> fut = std::async(ARM_random_infer_this_insn_propagate_next, func, func->start_ea);//execute thread with timeout
			//std::string function_name_string = "processing ";
			//function_name_string += function_name.c_str();
			//msg(function_name_string.c_str());
			//std::future_status status = fut.wait_for(std::chrono::seconds(5));
			//if (status == std::future_status::ready)//execution complete within time span
			//	;
			//else//execution exceed time span
			//	return;
			//ARM_translate_return_value(ea, func);
			ARM_translate_each_insn(func);
			ARM_delete_all_hash_tag(func);
			//ARM_display_translate_result(func);
			//ARM_analyze_conditional_jump(func);
			//print_conditional_jump(working_path);
			ARM_print_to_file(ea, one_function_path, func);
			//x64_clear_all();
		}
	}
}

//--------------------------------------------------------------------------
static plugmod_t *idaapi init()
{
  msg("Binary similarity detection::init\n");
  return new plugin_ctx_t;
}

//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_UNL            // Unload the plugin immediately after calling 'run'
  | PLUGIN_MULTI,       // The plugin can work with multiple idbs in parallel
  init,                 // initialize
  nullptr,
  nullptr,
  nullptr,              // long comment about the plugin
  nullptr,              // multiline help about the plugin
  "Binary similarity detection",       // the preferred short name of the plugin
  "F8",              // the preferred hotkey to run the plugin
};
