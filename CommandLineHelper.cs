using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;

namespace LowLevelDesign.Concerto
{
    public sealed class CommandLineArgumentException : Exception
    {
        public CommandLineArgumentException(string message) : base(message) { }
    }

    public static class CommandLineHelper
    {
        public static Dictionary<string, string> ParseArgs(string[] flagArgs, string[] rawArgs)
        {
            var args = rawArgs.SelectMany(arg => arg.Split(new[] { '=' },
                StringSplitOptions.RemoveEmptyEntries)).ToArray();
            bool IsFlag(string v) => Array.IndexOf(flagArgs, v) >= 0;

            var result = new Dictionary<string, string>(StringComparer.Ordinal);
            var lastArg = string.Empty;
            foreach (var arg in args) {
                switch (arg) {
                    case var s when s.StartsWith("-", StringComparison.Ordinal):
                        var option = s.TrimStart('-');
                        if (IsFlag(option)) {
                            Debug.Assert(lastArg == string.Empty);
                            result.Add(option, string.Empty);
                        } else {
                            Debug.Assert(lastArg == string.Empty);
                            lastArg = option;
                        }
                        break;
                    default:
                        if (lastArg != string.Empty) {
                            result.Add(lastArg, arg);
                            lastArg = string.Empty;
                        } else {
                            result[string.Empty] = !result.TryGetValue(string.Empty, out var freeArgs) ? arg : $"{freeArgs},{arg}";
                        }
                        break;
                }
            }
            return result;
        }
    }
}