package burp.scan.lib.utils;

import burp.scan.active.feature.Debug;
import burp.scan.lib.GlobalFunction;

public class Logger {
    enum Level {
        Debug(0x01),
        Info(0x02),Warning(0x03),Error(0x04);

        int level;
        Level(int i) {
            level = i;
        }

        int getLevel() {
            return level;
        }
    }

    Level level;

    public Logger(Level level) {
        this.level = level;
    }

    public static Logger getLogger(Level level) {
        return new Logger(level);
    }

    String getCaller() {
        return Thread.currentThread().getStackTrace()[3].toString();
    }
    public void debug(String message) {
        if (level.getLevel() <= Level.Debug.getLevel()) {
            GlobalFunction.callbacks.printOutput(String.format("[debug:%s] ",getCaller())+message);
        }
    }

    public void info(String message) {
        if (level.getLevel() <= Level.Info.getLevel()) {
            GlobalFunction.callbacks.printOutput(String.format("[info:%s] ",getCaller())+message);
        }
    }

    public void warning(String message) {
        if (level.getLevel() <= Level.Warning.getLevel()) {
            GlobalFunction.callbacks.printOutput(String.format("[warning:%s] ",getCaller())+message);
        }
    }

    public void error(String message) {
        if (level.getLevel() <= Level.Error.getLevel()) {
            GlobalFunction.callbacks.printError(String.format("[error:%s] ",getCaller())+message);
        }
    }

    public static Logger getLogger(Object obj) {
        if (obj instanceof Debug) {
            return getLogger(Level.Debug);
        }

        return getLogger(Level.Info);
    }
}
