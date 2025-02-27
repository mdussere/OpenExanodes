/*
 * Copyright 2002, 2009 Seanodes Ltd http://www.seanodes.com. All rights
 * reserved and protected by French, UK, U.S. and other countries' copyright laws.
 * This file is part of Exanodes project and is subject to the terms
 * and conditions defined in the LICENSE file which is present in the root
 * directory of the project.
 */
#ifndef __EXA_CLNODESTOP_H__
#define __EXA_CLNODESTOP_H__


#include "ui/cli/src/exa_clcommand.h"


template <bool is_clstop>
class exa_clXstop : public exa_clcommand
{
public:

    static const std::string OPT_ARG_NODE_HOSTNAMES;

    exa_clXstop();

    static constexpr const char *name() { return "exa_clnodestop"; }


    void run();

 protected:
  /* Used in clstop constructor */
  bool all_nodes;
  bool force;
  bool recursive;

  void dump_short_description (std::ostream& out, bool show_hidden = false) const;
  void dump_full_description(std::ostream& out, bool show_hidden = false) const;
  void dump_examples(std::ostream& out, bool show_hidden = false) const;

  void parse_opt_args (const std::map<char, std::string>& opt_args);

private:
    std::string node_expand;
    bool ignore_offline;
};


template <>
constexpr const char *exa_clXstop<true>::name() { return "exa_clstop"; }


using exa_clnodestop = exa_clXstop<false>;


#endif /* __EXA_CLNODESTOP_H__ */
