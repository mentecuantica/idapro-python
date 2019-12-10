'''
Example how to export named functions from IDA to JSON format
'''
import json

def to_file(idx,func_dict):
    jsname = "enf_func_"+str(idx)+".json"
    print(jsname)
    f = open(jsname, "w")
    json.dump(func_dict,f,indent=4,sort_keys=True)


def statistics(func_count, exported,file_count ):
    s = {
    'total_functions':func_count,
    'exported_names':exported,
    'files_count':file_count,
    }

    jsname = "enf_func_stat.json"
    f = open(jsname, "w")    
    json.dump(s,f,indent=4,sort_keys=True)
     
     
def export_named():
    file_limit = 2000
    cur = 0
    end = 150000
    file_count = 0
    total=0
    named_count=0
    named_funcs_dump = {}
    for faddr in Functions():
        total+=1
        fname = GetFunctionName(faddr)
        if 'sub_' in fname:
            continue
            
        named_funcs_dump[int(faddr)]=fname
        cur+=1
        named_count+=1
        if cur==file_limit:
            file_count+=1
            to_file(file_count,named_funcs_dump)
            named_funcs_dump = {}
            cur=0
    
        if total==end:
            print('Exception limit of' + str(end))
            break
        
    
    statistics(total,named_count,file_count)
export_named()
