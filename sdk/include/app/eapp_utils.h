//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#ifndef _EAPP_UTILS_
#define _EAPP_UTILS_

// This is a hacky way of getting the return value into a0, works for now
// 这是一种将返回值转换为 a0 的笨拙方法，目前有效
void
EAPP_RETURN(unsigned long rval) __attribute__((noreturn));

#define EAPP_ENTRY __attribute__((__section__(".text._start")))

#endif /* _EAPP_UTILS_ */
