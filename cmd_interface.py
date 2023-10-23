from prettytable import PrettyTable

def PrintInTerminal(process_info):
    field_names = list(process_info[0].keys())
    table = PrettyTable(field_names)
    for item in process_info:
        row = [item[field] for field in field_names]
        table.add_row(row)
    
    print(table)


