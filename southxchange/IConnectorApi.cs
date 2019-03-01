using System.Collections.Generic;

namespace Market.CurrencyManager.ConnectorApi
{
    public interface IConnectorApi
    {
        /// <summary>
        /// Logs a string
        /// </summary>
        /// <param name="log">Log message</param>
        void Log(string log);

        #region Storage methods
        /// <summary>
        /// Adds key/value pair removing existing keys
        /// </summary>
        /// <param name="key"></param>
        /// <param name="value"></param>
        void Replace(string key, string value);

        /// <summary>
        /// Adds a new key/value pair
        /// </summary>
        /// <param name="key"></param>
        /// <param name="value"></param>
        void Add(string key, string value);

        /// <summary>
        /// Removes all key/value pairs with specified key
        /// </summary>
        /// <param name="key"></param>
        void Delete(string key);

        /// <summary>
        /// Reads all values for a given key
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        List<string> Read(string key);

        /// <summary>
        /// Reads a single value for a given key. If there are multiple keys then a random value is returned
        /// </summary>
        /// <param name="key">Key</param>
        /// <returns>Value or null if it's not present</returns>
        string ReadOne(string key); 
        #endregion
    }
}
