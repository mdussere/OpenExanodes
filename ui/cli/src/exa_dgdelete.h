/*
 * Copyright 2002, 2009 Seanodes Ltd http://www.seanodes.com. All rights
 * reserved and protected by French, UK, U.S. and other countries' copyright laws.
 * This file is part of Exanodes project and is subject to the terms
 * and conditions defined in the LICENSE file which is present in the root
 * directory of the project.
 */
#ifndef  __EXA_DGDELETE_H__
#define  __EXA_DGDELETE_H__


#include "ui/cli/src/exa_dgcommand.h"

class exa_dgdelete : public exa_dgcommand
{

 public:

  exa_dgdelete();

  static constexpr const char *name() { return "exa_dgdelete"; }


  void run();

protected:

    void dump_short_description (std::ostream& out, bool show_hidden = false) const;
    void dump_full_description(std::ostream& out, bool show_hidden = false) const;
    void dump_examples(std::ostream& out, bool show_hidden = false) const;

    void parse_opt_args (const std::map<char, std::string>& opt_args);

 private:

  bool _forcemode;
  bool _recursive;

};


#endif  // __EXA_DGDELETE_H__
