#!/usr/bin/python
license_header =\
"""# SQLassie - database firewall
# Copyright (C) 2011 Brandon Skari <brandon.skari@gmail.com>
# 
# This file is part of SQLassie.
#
# SQLassie is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# SQLassie is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with SQLassie. If not, see <http://www.gnu.org/licenses/>.

"""

import os
import re
import sys
 
dot_ext_re = re.compile('\.[a-zA-Z]+')
include_re = re.compile('^#[ \t]*include[ \t]*')


class PrintWrapper:
	"""Handles wrapping while printing to a Makefile.

	Lines will be wrapped at wrap_length characters and the next line will
	start with a tab to indicate a continuation.
	"""

	def __init__(self, wrap_length=80, tab_width=8):
		self.WRAP_LENGTH = wrap_length
		self.TAB_WIDTH = tab_width
		self.column = 0
		self.new_line = False
	
	def write(self, string):
		# Leave an extra 2 spaces for the line continuation
		if self.column + len(string) < self.WRAP_LENGTH - 2:
			sys.stdout.write(string)
		else:
			sys.stdout.write(' \\\n')
			# When starting a new line, we don't need leading whitespace
			sys.stdout.write('\t' + string.lstrip())
			self.column = self.TAB_WIDTH

		self.column += len(string)


def print_dependencies(files):
	for file in files:
		inf = open(file)
		# Find local include files
		my_includes = set()
		for x in inf.readlines():
			m = include_re.search(x)
			if m != None:
				end_of_match = m.regs[0][1]
				x = x[end_of_match:-1]

				local_include = (x[0] == '"')
				if local_include:
					# Strip the quotes
					x = x[1:-1]
					# If the file is in a directory, get relative path
					if '..' + os.sep in x:
						x = x.replace('..' + os.sep, '')
						my_includes.add(x)
					elif os.path.dirname(file) != '':
						my_includes.add(os.path.dirname(file) + os.sep + x)
					else:
						my_includes.add(x)

		inf.close()
	 
		m = dot_ext_re.search(file)
		assert m != None
		start_of_match = m.regs[0][0]
		dot_o_file = file[:start_of_match] + '.o'

		wrapper = PrintWrapper()
		wrapper.write(dot_o_file + ':\t' + file)

		includes_list = list(my_includes)
		includes_list.sort()
		for x in includes_list:
			wrapper.write(' ' + x)

		sys.stdout.write('\n\n')

sys.stdout.write(license_header)
if len(sys.argv) > 1:
	print_dependencies(sys.argv[1:])
else:
	current_dir = [f for f in os.listdir('.') if f.endswith('.cpp')]
	current_dir.sort()
	print_dependencies(current_dir)
