#region Copyright

/*
 * Copyright (C) 2018 Larry Lopez
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#endregion Copyright

using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Reflection;
using System.Reflection.Emit;
using System.Security.Cryptography;

namespace Hashlib.NET.Common
{
    /// <summary>
    /// A static factory for creating <see cref="HashAlgorithm"/> derived classes.
    /// </summary>
    /// <remarks>
    /// Dynamically finds all classes derived from <see cref="HashAlgorithm"/> in the assembly and
    /// registers them for creation.
    /// </remarks>
    public static class HashAlgorithmFactory
    {
        #region Fields

        private static readonly ConcurrentDictionary<string, ConstructorDelegate> classConstructors;
        private static readonly ConcurrentDictionary<string, Type> classRegistry;
        private static readonly Type classType;
        private static readonly Type[] constructorArgs;

        #endregion Fields

        #region Delegates

        private delegate HashAlgorithm ConstructorDelegate();

        #endregion Delegates

        #region Constructors

        /// <summary>
        /// Static constructor for initializing and registering all supported classes dynamically.
        /// </summary>
        static HashAlgorithmFactory()
        {
            classType = typeof(HashAlgorithm);
            constructorArgs = new Type[] { };
            classRegistry = new ConcurrentDictionary<string, Type>();
            classConstructors = new ConcurrentDictionary<string, ConstructorDelegate>();

            var assembly = Assembly.GetEntryAssembly() ?? Assembly.GetExecutingAssembly();
            var hashAlgorithms = from b in assembly.GetTypes()
                                 where !b.IsInterface
                                 && !b.IsAbstract
                                 && b.IsSubclassOf(classType)
                                 select b;

            foreach (var type in hashAlgorithms)
            {
                classRegistry.TryAdd(type.Name, type);
            }
        }

        #endregion Constructors

        #region Methods

        /// <summary>
        /// Static method for creating <see cref="HashAlgorithm"/> derived class instances.
        /// </summary>
        /// <param name="identifier">Name of the class instance to create.</param>
        /// <returns>A <see cref="HashAlgorithm"/> derived class instance.</returns>
        public static HashAlgorithm Create(string identifier)
        {
            if (string.IsNullOrEmpty(identifier))
            {
                throw new ArgumentException("Identifiier can not be null or empty", nameof(identifier));
            }

            if (!classRegistry.ContainsKey(identifier))
            {
                throw new ArgumentException("No HashAlgorithm has been registered with the given identifier",
                    nameof(identifier));
            }

            return Create(classRegistry[identifier]);
        }

        /// <summary>
        /// Static method for creating <see cref="HashAlgorithm"/> derived class instances.
        /// </summary>
        /// <param name="type">The object type to create an instance.</param>
        /// <returns>A <see cref="HashAlgorithm"/> derived class instance.</returns>
        private static HashAlgorithm Create(Type type)
        {
            if (type == null)
            {
                throw new ArgumentNullException(nameof(type));
            }

            if (classConstructors.TryGetValue(type.Name, out ConstructorDelegate del))
            {
                return del();
            }

            DynamicMethod dynamicMethod = new DynamicMethod("CreateInstance", classType, constructorArgs, type);
            ILGenerator ilGenerator = dynamicMethod.GetILGenerator();

            ilGenerator.Emit(OpCodes.Newobj, type.GetConstructor(constructorArgs));
            ilGenerator.Emit(OpCodes.Ret);

            del = (ConstructorDelegate)dynamicMethod.CreateDelegate(typeof(ConstructorDelegate));
            classConstructors.TryAdd(type.Name, del);
            return del();
        }

        #endregion Methods
    }
}