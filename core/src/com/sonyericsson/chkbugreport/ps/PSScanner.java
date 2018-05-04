/*
 * Copyright (C) 2011 Sony Ericsson Mobile Communications AB
 * Copyright (C) 2012 Sony Mobile Communications AB
 *
 * This file is part of ChkBugReport.
 *
 * ChkBugReport is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * ChkBugReport is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with ChkBugReport.  If not, see <http://www.gnu.org/licenses/>.
 */
package com.sonyericsson.chkbugreport.ps;

import com.sonyericsson.chkbugreport.BugReportModule;
import com.sonyericsson.chkbugreport.ProcessRecord;
import com.sonyericsson.chkbugreport.Section;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class PSScanner {
    private static final Pattern HEADER = Pattern.compile("USER +PID +(TID +)?PPID");

    private BugReportModule mBr;

    public PSScanner(BugReportModule br) {
        mBr = br;
    }

    public PSRecords run() {
        PSRecords ret = readPS(Section.PROCESSES_AND_THREADS);
        if (ret == null) {
            ret = readPS(Section.PROCESSES);
        }
        return ret;
    }

    private String ensureItemWithOffset(int index, int size, String[] item) {
        if (item.length == size) {
            return item[index];
        } else {
            // Some item is missed, return the item backwards
            return item[item.length - 1 - (size - index)];
        }
    }

    private PSRecords readPS(String sectionName) {
        Section ps = mBr.findSection(sectionName);
        if (ps == null) {
            mBr.printErr(3, "Cannot find section: " + sectionName + " (ignoring it)");
            return null;
        }

        // Process the PS section
        PSRecords ret = new PSRecords();
        int lineIdx = 0, idxUser = -1, idxPid = -1, idxPPid = -1, idxPcy = -1, idxName = -1, idxNice = -1, size = 0;
        for (int tries = 0; tries < 10 && lineIdx < ps.getLineCount(); tries++) {
            String buff = ps.getLine(lineIdx++);
            Matcher matcher = HEADER.matcher(buff);
            if (matcher.find()) {
                String items[] = buff.split("\\s+");
                size = items.length;
                for (int i = 0; i < size; i++) {
                    if ("USER".equals(items[i])) {
                        idxUser = i;
                    } else if ("PID".equals(items[i])) {
                        idxPid = i;
                    } else if ("PPID".equals(items[i])) {
                        idxPPid = i;
                    } else if ("NICE".equals(items[i]) || "NI".equals(items[i])) {
                        idxNice = i;
                    } else if ("PCY".equals(items[i])) {
                        idxPcy = i;
                    } else if ("NAME".equals(items[i]) || "CMD".equals(items[i])) {
                        idxName = i;
                    }
                }
                break;
            }
        }
        if (idxPid == -1) {
            mBr.printErr(4, "Could not find header in ps output");
            return null;
        }

        // Now read and process every line
        int pidZygote = -1;
        int cnt = ps.getLineCount();
        for (int i = lineIdx; i < cnt; i++) {
            String buff = ps.getLine(i);
            if (buff.startsWith("[")) break;

            String items[] = buff.split("\\s+", size);
            // WCHAN might be empty, the item size might be tightly different
            if (items.length < size - 1) {
                mBr.printErr(4, "Error parsing line: " + buff);
                continue;
            }

            int pid = -1;
            if (idxPid >= 0) {
                String sPid = items[idxPid];
                try {
                    pid = Integer.parseInt(sPid);
                } catch (NumberFormatException nfe) {
                    mBr.printErr(4, "Error parsing pid from: " + sPid);
                    break;
                }
            }

            // Extract ppid
            int ppid = -1;
            if (idxPPid >= 0) {
                String sPid = items[idxPPid];
                try {
                    ppid = Integer.parseInt(sPid);
                } catch (NumberFormatException nfe) {
                    mBr.printErr(4, "Error parsing ppid from: " + sPid);
                    break;
                }
            }

            // Extract nice
            int nice = PSRecord.NICE_UNKNOWN;
            if (idxNice >= 0) {
                String sNice = ensureItemWithOffset(idxNice, size, items);
                try {
                    nice = Integer.parseInt(sNice);
                } catch (NumberFormatException nfe) {
                    mBr.printErr(4, "Error parsing nice from: " + sNice);
                    break;
                }
            }

            // Extract scheduler policy
            int pcy = PSRecord.PCY_UNKNOWN;
            if (idxPcy >= 0) {
                String sPcy = ensureItemWithOffset(idxPcy, size, items);
                if ("fg".equals(sPcy)) {
                    pcy = PSRecord.PCY_NORMAL;
                } else if ("bg".equals(sPcy)) {
                    pcy = PSRecord.PCY_BATCH;
                } else if ("un".equals(sPcy)) {
                    pcy = PSRecord.PCY_FIFO;
                } else {
                    pcy = PSRecord.PCY_OTHER;
                }
            }

            // Exctract name
            String name = "";
            if (idxName >= 0) {
                name = ensureItemWithOffset(idxName, size, items);
                // Header might not contain the item "S" with "ps -P"
                if (name.startsWith("S ")) name = name.substring(2);
            }

            // Extract user
            String user = "";
            if (idxUser >= 0) {
                user = ensureItemWithOffset(idxUser, size, items);
            }

            // Fix the name
            ret.put(pid, new PSRecord(pid, ppid, nice, pcy, name, user));

            // Check if we should create a ProcessRecord for this
            if (pidZygote == -1 && name.equals("zygote")) {
                pidZygote = pid;
            }
            ProcessRecord pr = mBr.getProcessRecord(pid, true, false);
            pr.suggestName(name, 10);
        }

        // Build tree structure as well
        for (PSRecord psr : ret) {
            int ppid = psr.mPPid;
            PSRecord parent = ret.getPSRecord(ppid);
            if (parent == null) {
                parent = ret.getPSTree();
            }
            parent.mChildren.add(psr);
            psr.mParent = parent;
        }

        return ret;
    }

}
