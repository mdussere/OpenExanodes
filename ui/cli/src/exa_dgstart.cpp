/*
 * Copyright 2002, 2009 Seanodes Ltd http://www.seanodes.com. All rights
 * reserved and protected by French, UK, U.S. and other countries' copyright laws.
 * This file is part of Exanodes project and is subject to the terms
 * and conditions defined in the LICENSE file which is present in the root
 * directory of the project.
 */
#include "ui/cli/src/exa_dgstart.h"

#include "ui/common/include/admindcommand.h"
#include "ui/common/include/cli_log.h"

using std::string;

exa_dgstart::exa_dgstart()
{
    add_see_also({ "exa_dgcreate",
                   "exa_dgdelete",
                   "exa_dgstop",
                   "exa_dgdiskrecover" });
}


void exa_dgstart::run()
{
    string error_msg;

    if (set_cluster_from_cache(_cluster_name, error_msg) != EXA_SUCCESS)
        throw CommandException(EXA_ERR_DEFAULT);

    exa_cli_trace("cluster=%s\n", exa.get_cluster().c_str());

    /*
     * Create command
     */
    AdmindCommand command("dgstart", exa.get_cluster_uuid());
    command.add_param("groupname", _group_name);

    printf("Starting group '%s' for cluster '%s'\n",
           _group_name.c_str(),
           exa.get_cluster().c_str());

    /* Send the command and receive the response */
    exa_error_code error_code;
    string error_message;
    send_command(command, "Group start:", error_code, error_message);

    if (error_code != EXA_SUCCESS)
        throw CommandException(error_code);
}


std::string exa_dgstart::get_short_description(bool) const
{
    return "Start an Exanodes disk group.";
}


std::string exa_dgstart::get_full_description(bool show_hidden) const
{
    return "Start the disk group " + ARG_DISKGROUP_GROUPNAME
           + " of the cluster " + ARG_DISKGROUP_CLUSTERNAME;
}


void exa_dgstart::dump_examples(std::ostream &out, bool show_hidden) const
{
    out << "Start the disk group " << Boldify("mygroup") << " in the cluster "
        << Boldify("mycluster") << ":" << std::endl;
    out << "  " << "exa_dgstart mycluster:mygroup" << std::endl;
    out << std::endl;
}


