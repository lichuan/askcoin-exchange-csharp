using System;
using System.Collections.Generic;
using System.Text;
using System.Net;
using System.Threading;
using System.Net.WebSockets;
using System.Text.RegularExpressions;
using System.Security.Cryptography;
using Market.CurrencyManager.ConnectorApi;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Cryptography.ECDSA;

namespace Askcoin
{
    public class AskcoinConnector : IConnector
    {
        IConnectorApi m_conn_api;
        ClientWebSocket m_wsock;
        uint m_cur_msg_id = 0;
        CancellationToken m_cancel_token = new CancellationToken();
        int m_required_confirms = 50;

        // change to your own exchange account privkey
        string m_exchange_account_privkey = "NdwJnIHm9oU+IPu7qPr/DcbgbVLd4Sf2trGgxHm1qxw=";

        public void SetApi(IConnectorApi connectorApi)
        {
            m_conn_api = connectorApi;
        }

        /// <summary>
        /// Returns a list of deposits. It must return pending and confirmed deposits. Ideally confirmed deposits
        /// should be returned only once, but if they are returned multiple times then it's okay (i.e. they won't be
        /// credited multiple times). Pending deposits can be returned in multiple invocations until they become confirmed.
        /// BatchId is an identifier that is passed between calls to ListDeposits. Each call includes the last returned
        /// BatchId (as part of DepositList object). It can be any string, but it usually is the block ID of the last
        /// processed block.
        /// </summary>
        /// <returns>Batch ID of the previous call, or null on the first time</returns>
        public DepositList ListDeposits(string batchId)
        {          
            ulong block_id;
            bool result = ulong.TryParse(batchId, out block_id);
            if(!result)
            {
                Console.WriteLine("failed");
            }            
            Console.WriteLine("block_id: {0}", block_id);            
            JObject obj = new JObject();
            obj.Add("msg_type", 6);
            obj.Add("msg_cmd", 7);
            obj.Add("msg_id", ++m_cur_msg_id);
            obj.Add("required_confirms", m_required_confirms);
            obj.Add("block_id", block_id);

            DepositList dlist = new DepositList();
            dlist.Deposits = new List<Deposit>();            

            string obj_str = JsonConvert.SerializeObject(obj);
            byte[] arr = System.Text.Encoding.Default.GetBytes(obj_str);
            var send_task = m_wsock.SendAsync(new ArraySegment<byte>(arr), WebSocketMessageType.Text, true, m_cancel_token);
            send_task.Wait();
            

            while (true)
            {
                byte[] recv_arr = new byte[500 * 1024];
                var recv_task = m_wsock.ReceiveAsync(new ArraySegment<byte>(recv_arr), m_cancel_token);
                WebSocketReceiveResult res = recv_task.Result;
                byte[] data_arr = new byte[res.Count];
                Array.Copy(recv_arr, data_arr, res.Count);
                string recv_str = System.Text.Encoding.Default.GetString(data_arr);
                Console.WriteLine(recv_str);
                var recv_obj = (JObject)JsonConvert.DeserializeObject(recv_str);
                uint recv_msg_id = (uint)recv_obj.Property("msg_id");

                if (recv_msg_id == m_cur_msg_id)
                {
                    var deposits_json = recv_obj["deposits"];
                    dlist.BatchId = (string)recv_obj["batchId"];

                    Console.WriteLine("batchId: {0}", dlist.BatchId);

                    foreach (var dobj in deposits_json)
                    {
                        JObject deposit_obj = (JObject)dobj;
                        //Console.WriteLine(deposit_obj);
                        Deposit dp = new Deposit();
                        
                        if(deposit_obj["memo"] != null)
                        {
                            dp.Address = (string)deposit_obj["memo"];                            
                        }

                        dp.Amount = (decimal)deposit_obj["amount"];
                        dp.Confirmations = (int)deposit_obj["confirms"];
                        dp.Confirmed = (bool)deposit_obj["confirmed"];
                        dp.TxId = (string)deposit_obj["tx_id"];
                        dlist.Deposits.Add(dp);                        
                    }

                    Console.WriteLine("listdeposits ok");                
                    break;
                }
            }

            return dlist;
        }

        public WithdrawList ListWithdraws(string batchId)
        {
            ulong block_id;
            bool result = ulong.TryParse(batchId, out block_id);
            if (!result)
            {
                Console.WriteLine("failed");
            }
            Console.WriteLine("block_id: {0}", block_id);
            JObject obj = new JObject();
            obj.Add("msg_type", 6);
            obj.Add("msg_cmd", 8);
            obj.Add("msg_id", ++m_cur_msg_id);
            obj.Add("required_confirms", m_required_confirms);
            obj.Add("block_id", block_id);

            WithdrawList wlist = new WithdrawList();
            wlist.Withdraws = new List<Withdraw>();            

            string obj_str = JsonConvert.SerializeObject(obj);
            byte[] arr = System.Text.Encoding.Default.GetBytes(obj_str);
            var send_task = m_wsock.SendAsync(new ArraySegment<byte>(arr), WebSocketMessageType.Text, true, m_cancel_token);
            send_task.Wait();
            

            while (true)
            {
                byte[] recv_arr = new byte[500 * 1024];
                var recv_task = m_wsock.ReceiveAsync(new ArraySegment<byte>(recv_arr), m_cancel_token);
                WebSocketReceiveResult res = recv_task.Result;
                byte[] data_arr = new byte[res.Count];
                Array.Copy(recv_arr, data_arr, res.Count);
                string recv_str = System.Text.Encoding.Default.GetString(data_arr);
                Console.WriteLine(recv_str);
                var recv_obj = (JObject)JsonConvert.DeserializeObject(recv_str);
                uint recv_msg_id = (uint)recv_obj.Property("msg_id");

                if (recv_msg_id == m_cur_msg_id)
                {
                    var withdraws_json = recv_obj["withdraws"];
                    wlist.BatchId = (string)recv_obj["batchId"];

                    foreach (var wobj in withdraws_json)
                    {
                        JObject withdraw_obj = (JObject)wobj;
                        //Console.WriteLine(withdraw_obj);
                        Withdraw wd = new Withdraw();
                        wd.Address = (string)withdraw_obj["receiver_id"];
                        wd.Amount = (decimal)withdraw_obj["amount"];
                        wd.Confirmations = (int)withdraw_obj["confirms"];
                        wd.Confirmed = (bool)withdraw_obj["confirmed"];
                        wd.TxId = (string)withdraw_obj["tx_id"];
                        wlist.Withdraws.Add(wd);
                    }

                    Console.WriteLine("listwithdraws ok");
                    break;
                }
            }

            return wlist;         
        }

        /// <summary>
        /// Unlocks the wallet to send
        /// </summary>
        /// <param name="key">Current key</param>
        public void Unlock(string key)
        {        
            JObject obj = new JObject();
            obj.Add("msg_type", 6);
            obj.Add("msg_cmd", 5);
            obj.Add("msg_id", ++m_cur_msg_id);
            obj.Add("password", key);

            string obj_str = JsonConvert.SerializeObject(obj);
            byte[] arr = System.Text.Encoding.Default.GetBytes(obj_str);
            var send_task = m_wsock.SendAsync(new ArraySegment<byte>(arr), WebSocketMessageType.Text, true, m_cancel_token);
            send_task.Wait();        

            while (true)
            {
                byte[] recv_arr = new byte[100 * 1024];
                var recv_task = m_wsock.ReceiveAsync(new ArraySegment<byte>(recv_arr), m_cancel_token);
                WebSocketReceiveResult res = recv_task.Result;
                byte[] data_arr = new byte[res.Count];
                Array.Copy(recv_arr, data_arr, res.Count);
                string recv_str = System.Text.Encoding.Default.GetString(data_arr);               
                var recv_obj = (JObject)JsonConvert.DeserializeObject(recv_str);
                uint recv_msg_id = (uint)recv_obj.Property("msg_id");

                if (recv_msg_id == m_cur_msg_id)
                {
                    if(recv_obj["err_code"] != null)
                    {
                        Console.WriteLine("unlock: error happened");                       
                    }
                    else
                    {
                        Console.WriteLine("unlock success");
                    }

                    break;                  
                }
            }
        }

        /// <summary>
        /// Locks the wallets
        /// </summary>
        public void Lock()
        {
            JObject obj = new JObject();
            obj.Add("msg_type", 6);
            obj.Add("msg_cmd", 4);
            obj.Add("msg_id", ++m_cur_msg_id);            

            string obj_str = JsonConvert.SerializeObject(obj);
            byte[] arr = System.Text.Encoding.Default.GetBytes(obj_str);
            var send_task = m_wsock.SendAsync(new ArraySegment<byte>(arr), WebSocketMessageType.Text, true, m_cancel_token);
            send_task.Wait();

            while (true)
            {
                byte[] recv_arr = new byte[100 * 1024];
                var recv_task = m_wsock.ReceiveAsync(new ArraySegment<byte>(recv_arr), m_cancel_token);
                WebSocketReceiveResult res = recv_task.Result;
                byte[] data_arr = new byte[res.Count];
                Array.Copy(recv_arr, data_arr, res.Count);
                string recv_str = System.Text.Encoding.Default.GetString(data_arr);
                var recv_obj = (JObject)JsonConvert.DeserializeObject(recv_str);
                uint recv_msg_id = (uint)recv_obj.Property("msg_id");

                if (recv_msg_id == m_cur_msg_id)
                {                  
                    break;
                }
            }

        }

        /// <summary>
        /// Changes the encryption key
        /// </summary>
        /// <param name="key">Current key, or null if wallet is not encrypted yet</param>
        /// <param name="newKey">New key</param>
        public void ChangeKey(string key, string newKey)
        {
            JObject obj = new JObject();
            obj.Add("msg_type", 6);
            obj.Add("msg_cmd", 6);
            obj.Add("msg_id", ++m_cur_msg_id);

            if(key != null)
            {
                obj.Add("key", key);
            }
            
            obj.Add("newkey", newKey);

            string obj_str = JsonConvert.SerializeObject(obj);
            byte[] arr = System.Text.Encoding.Default.GetBytes(obj_str);
            var send_task = m_wsock.SendAsync(new ArraySegment<byte>(arr), WebSocketMessageType.Text, true, m_cancel_token);
            send_task.Wait();

            while (true)
            {
                byte[] recv_arr = new byte[100 * 1024];
                var recv_task = m_wsock.ReceiveAsync(new ArraySegment<byte>(recv_arr), m_cancel_token);
                WebSocketReceiveResult res = recv_task.Result;
                byte[] data_arr = new byte[res.Count];
                Array.Copy(recv_arr, data_arr, res.Count);
                string recv_str = System.Text.Encoding.Default.GetString(data_arr);
                var recv_obj = (JObject)JsonConvert.DeserializeObject(recv_str);
                uint recv_msg_id = (uint)recv_obj.Property("msg_id");

                if (recv_msg_id == m_cur_msg_id)
                {
                    if (recv_obj["err_code"] != null)
                    {
                        Console.WriteLine("changekey: error happened");
                    }
                    else
                    {
                        Console.WriteLine("changekey success");
                    }

                    break;
                }
            }

        }

        /// <summary>
        /// Verifies if a given string is a valid address
        /// </summary>
        /// <param name="address">Address to check</param>
        /// <returns>True if address is valid, False otherwise</returns>
        public bool IsAddressValid(string address)
        {
            return Regex.IsMatch(address, "^[1-9][0-9]*$");           
        }

        public byte[] CompactToDer(byte[] compact_sign)
        {
            List<byte> r = new List<byte>();
            List<byte> s = new List<byte>();

            if(compact_sign[0] > 0x7f)
            {
                r.Add(0);
            }
            
            for(var i = 0; i < 32; ++i)
            {
                r.Add(compact_sign[i]);
            }

            if(compact_sign[32] > 0x7f)
            {
                s.Add(0);
            }
            
            for (var i = 32; i < 64; ++i)
            {
                s.Add(compact_sign[i]);
            }

            List<byte> der_sign = new List<byte>();
            der_sign.Add(0x30);
            der_sign.Add((byte)(4 + r.Count + s.Count));
            der_sign.Add(0x02);
            der_sign.Add((byte)(r.Count));
            der_sign.AddRange(r);
            der_sign.Add(0x02);
            der_sign.Add((byte)(s.Count));
            der_sign.AddRange(s);

            return der_sign.ToArray();
        }

        /// <summary>
        /// Sends a given amount to a destination address, and returns transaction ID (hash)
        /// </summary>
        /// <param name="address">Destination address</param>
        /// <param name="amount">Amount to send</param>
        /// <returns>Transaction ID</returns>
        public string SendTo(string address, decimal _amount)
        {
            ulong account_id;
            bool result = ulong.TryParse(address, out account_id);
            uint amount = (uint)_amount;
            
            if (!result)
            {
                Console.WriteLine("failed");
            }

            string receiver_pubkey;

            // query receiver's pubkey            
            JObject obj = new JObject();
            obj.Add("msg_type", 1);
            obj.Add("msg_cmd", 3);
            obj.Add("msg_id", ++m_cur_msg_id);
            obj.Add("id", account_id);

            string obj_str = JsonConvert.SerializeObject(obj);
            byte[] arr = System.Text.Encoding.Default.GetBytes(obj_str);
            var send_task = m_wsock.SendAsync(new ArraySegment<byte>(arr), WebSocketMessageType.Text, true, m_cancel_token);
            send_task.Wait();

            while (true)
            {
                byte[] recv_arr = new byte[100 * 1024];
                var recv_task = m_wsock.ReceiveAsync(new ArraySegment<byte>(recv_arr), m_cancel_token);
                WebSocketReceiveResult res = recv_task.Result;
                byte[] data_arr = new byte[res.Count];
                Array.Copy(recv_arr, data_arr, res.Count);
                string recv_str = System.Text.Encoding.Default.GetString(data_arr);
                var recv_obj = (JObject)JsonConvert.DeserializeObject(recv_str);
                uint recv_msg_id = (uint)recv_obj.Property("msg_id");

                if (recv_msg_id == m_cur_msg_id)
                {
                    if (recv_obj["err_code"] != null)
                    {
                        Console.WriteLine("error happened");
                        return "no_tx_id";
                    }
                    else
                    {                      
                        receiver_pubkey = (string)recv_obj["pubkey"];
                    }

                    break;
                }
            }      

            // query latest_block_id
            Info info = GetInfo();
            long latest_block_id = info.LastBlock;
        
            JObject obj_data = new JObject();
            obj_data.Add("type", 2);
            DateTime now = DateTime.UtcNow;
            long utc = now.Ticks - DateTime.Parse("1970-01-01 00:00:00").Ticks;
            utc /= 10000000;           
            obj_data.Add("utc", utc);
            obj_data.Add("block_id", latest_block_id);
            obj_data.Add("fee", 2);
            obj_data.Add("amount", amount);
            byte[] privkey = Convert.FromBase64String(m_exchange_account_privkey);
            byte[] pubkey = Secp256K1Manager.GetPublicKey(privkey, false);
            obj_data.Add("pubkey", Convert.ToBase64String(pubkey));
            obj_data.Add("receiver", receiver_pubkey);
            string obj_data_str = JsonConvert.SerializeObject(obj_data);           
            //Console.WriteLine(obj_data_str);
            byte[] obj_data_arr = System.Text.Encoding.Default.GetBytes(obj_data_str);
            byte[] tx_hash_raw = Sha256Manager.GetHash(obj_data_arr);
            tx_hash_raw = Sha256Manager.GetHash(tx_hash_raw);
            string tx_hash_b64 = Convert.ToBase64String(tx_hash_raw);                    
            int recover_id;
            byte[] sign_raw = Secp256K1Manager.SignCompact(tx_hash_raw, privkey, out recover_id);         
            sign_raw = CompactToDer(sign_raw);           
            string sign_b64 = Convert.ToBase64String(sign_raw);           
            JObject obj_1 = new JObject();
            obj_1.Add("msg_type", 2);
            obj_1.Add("msg_cmd", 0);
            obj_1.Add("msg_id", ++m_cur_msg_id);
            obj_1.Add("data", obj_data);
            obj_1.Add("sign", sign_b64);
            string obj_str_1 = JsonConvert.SerializeObject(obj_1);
            //Console.WriteLine(obj_str_1);
           
            byte[] arr_1 = System.Text.Encoding.Default.GetBytes(obj_str_1);            
            var send_task_1 = m_wsock.SendAsync(new ArraySegment<byte>(arr_1), WebSocketMessageType.Text, true, m_cancel_token);
            send_task_1.Wait();

            while (true)
            {
                byte[] recv_arr = new byte[100 * 1024];
                var recv_task = m_wsock.ReceiveAsync(new ArraySegment<byte>(recv_arr), m_cancel_token);
                WebSocketReceiveResult res = recv_task.Result;
                byte[] data_arr = new byte[res.Count];
                Array.Copy(recv_arr, data_arr, res.Count);
                string recv_str = System.Text.Encoding.Default.GetString(data_arr);
                var recv_obj = (JObject)JsonConvert.DeserializeObject(recv_str);
                uint recv_msg_id = (uint)recv_obj.Property("msg_id");

                if (recv_msg_id == m_cur_msg_id)
                {
                    if (recv_obj["err_code"] != null)
                    {
                        Console.WriteLine("error happened");
                        return "no_tx_id";
                    }

                    break;
                }
            }

            return tx_hash_b64;
        }

        /// <summary>
        /// Returns the fees consumed by a given transaction ID. It is always called for a transaction
        /// generated by this wallet (e.g. previously returned by SendTo)
        /// </summary>
        /// <param name="txId">Transaction ID</param>
        /// <returns>Fees</returns>
        public decimal GetTransactionFees(string txId)
        {
            return 2;
        }

        /// <summary>
        /// Generates a new deposit address
        /// </summary>
        /// <returns>New deposit address</returns>
        public string GenerateAddress()
        {
            return "askcoin is account-based, so no need generate address, use the 'memo' to identify your users";
        }

        /// <summary>
        /// Verifies if the wallet is currently encrypted
        /// </summary>
        /// <returns>True if wallet is encrypted, False otherwise</returns>
        public bool IsEncrypted()
        {
            JObject obj = new JObject();
            obj.Add("msg_type", 6);
            obj.Add("msg_cmd", 9);
            obj.Add("msg_id", ++m_cur_msg_id);           

            string obj_str = JsonConvert.SerializeObject(obj);
            byte[] arr = System.Text.Encoding.Default.GetBytes(obj_str);
            var send_task = m_wsock.SendAsync(new ArraySegment<byte>(arr), WebSocketMessageType.Text, true, m_cancel_token);
            send_task.Wait();

            while (true)
            {
                byte[] recv_arr = new byte[100 * 1024];
                var recv_task = m_wsock.ReceiveAsync(new ArraySegment<byte>(recv_arr), m_cancel_token);
                WebSocketReceiveResult res = recv_task.Result;
                byte[] data_arr = new byte[res.Count];
                Array.Copy(recv_arr, data_arr, res.Count);
                string recv_str = System.Text.Encoding.Default.GetString(data_arr);
                var recv_obj = (JObject)JsonConvert.DeserializeObject(recv_str);
                uint recv_msg_id = (uint)recv_obj.Property("msg_id");

                if (recv_msg_id == m_cur_msg_id)
                {
                    bool is_locked = (bool)recv_obj["is_locked"];

                    return is_locked;
                }
            }
        }

        /// <summary>
        /// Returns when the wallet is reachable and working properly. If server
        /// is not reachable then simply throw an exception instead of waiting.
        /// </summary>
        public void Ping()
        {
            JObject obj = new JObject();
            obj.Add("msg_type", 0);
            obj.Add("msg_cmd", 0);
            obj.Add("msg_id", ++m_cur_msg_id);
            string obj_str = JsonConvert.SerializeObject(obj);
            byte[] arr = System.Text.Encoding.Default.GetBytes(obj_str);
            var send_task = m_wsock.SendAsync(new ArraySegment<byte>(arr), WebSocketMessageType.Text, true, m_cancel_token);
            send_task.Wait();

            while (true)
            {    
                byte[] recv_arr = new byte[100 * 1024];
                var recv_task = m_wsock.ReceiveAsync(new ArraySegment<byte>(recv_arr), m_cancel_token);
                WebSocketReceiveResult res = recv_task.Result;
                byte[] data_arr = new byte[res.Count];
                Array.Copy(recv_arr, data_arr, res.Count);
                string recv_str = System.Text.Encoding.Default.GetString(data_arr);
                var recv_obj = (JObject)JsonConvert.DeserializeObject(recv_str);
                uint recv_msg_id = (uint)recv_obj.Property("msg_id");

                if(recv_msg_id == m_cur_msg_id)
                {
                    break;
                }
            }

            Console.WriteLine("ping ok");
        }

        /// <summary>
        /// Returns information regarding the wallet
        /// </summary>
        /// <returns>Wallet info</returns>
        public Info GetInfo()
        {
            JObject obj = new JObject();
            obj.Add("msg_type", 6);
            obj.Add("msg_cmd", 10);
            obj.Add("msg_id", ++m_cur_msg_id);

            string obj_str = JsonConvert.SerializeObject(obj);
            byte[] arr = System.Text.Encoding.Default.GetBytes(obj_str);
            var send_task = m_wsock.SendAsync(new ArraySegment<byte>(arr), WebSocketMessageType.Text, true, m_cancel_token);
            send_task.Wait();
            Info info = new Info();

            while (true)
            {
                byte[] recv_arr = new byte[100 * 1024];
                var recv_task = m_wsock.ReceiveAsync(new ArraySegment<byte>(recv_arr), m_cancel_token);
                WebSocketReceiveResult res = recv_task.Result;
                byte[] data_arr = new byte[res.Count];
                Array.Copy(recv_arr, data_arr, res.Count);
                string recv_str = System.Text.Encoding.Default.GetString(data_arr);
                var recv_obj = (JObject)JsonConvert.DeserializeObject(recv_str);
                uint recv_msg_id = (uint)recv_obj.Property("msg_id");

                if (recv_msg_id == m_cur_msg_id)
                {
                    info.Connections = (int)recv_obj["connections"];
                    info.LastBlock = (long)recv_obj["latest_block_id"];
                    info.Reserves = (decimal)recv_obj["reserves"];
                    info.Version = (string)recv_obj["version"];

                    break;                   
                }
            }
            
            return info;
        }

        /// <summary>
        /// Returns the number of confirmations required to confirm deposits
        /// </summary>
        /// <returns>Confirmations required</returns>
        public int GetRequiredConfirmations()
        {
            return m_required_confirms;
        }

        public void Main()
        {
            /* FYI: c++ full node message enum
            enum MSG_TYPE
            {
                MSG_SYS,
                MSG_ACCOUNT,
                MSG_TX,
                MSG_BLOCK,
                MSG_TOPIC,
                MSG_EXPLORER,
                MSG_EXCHANGE
            };

            enum MSG_CMD
            {
                SYS_PING,
                SYS_PONG,
                SYS_INFO,

                ACCOUNT_IMPORT = 0,
                ACCOUNT_TOP100,
                ACCOUNT_PROBE,
                ACCOUNT_QUERY,
                ACCOUNT_HISTORY,

                TX_CMD = 0,

                BLOCK_SYNC = 0,

                TOPIC_QUESTION_PROBE = 0,
                TOPIC_DETAIL_PROBE,
                TOPIC_LIST,
                TOPIC_ANSWER_LIST,

                EXPLORER_MAIN_PAGE = 0,
                EXPLORER_NEXT_PAGE,
                EXPLORER_BLOCK_PAGE,
                EXPLORER_TX_PAGE,
                EXPLORER_ACCOUNT_PAGE,
                EXPLORER_QUERY,

                EXCHANGE_LOGIN = 0,
                EXCHANGE_NOTIFY_DEPOSIT,
                EXCHANGE_DEPOSIT_TX_PROBE,
                EXCHANGE_WITHDRAW_TX_PROBE,
                EXCHANGE_LOCK,
                EXCHANGE_UNLOCK,
                EXCHANGE_CHANGE_KEY,
                EXCHANGE_LIST_DEPOSIT,
                EXCHANGE_LIST_WITHDRAW,
                EXCHANGE_IS_LOCKED,
                EXCHANGE_INFO              
            };
            */


            // connect to your full node
            m_wsock = new ClientWebSocket();
            var conn_task = m_wsock.ConnectAsync(new Uri("ws://your_full_node.com:19050"), m_cancel_token);
            conn_task.Wait();


            // login to your full node, use your own account and password
            string login_password = "exchange_password";
            string exchange_account_b64 = "YXNrY29pbg==";
            uint exchange_account_id = 3;

            JObject obj = new JObject();
            obj.Add("msg_type", 6);
            obj.Add("msg_cmd", 0);
            obj.Add("msg_id", ++m_cur_msg_id);
            obj.Add("account_id", exchange_account_id);
            obj.Add("account_b64", exchange_account_b64);
            obj.Add("password", login_password);
            string obj_str = JsonConvert.SerializeObject(obj);
            byte[] arr = System.Text.Encoding.Default.GetBytes(obj_str);
            var send_task = m_wsock.SendAsync(new ArraySegment<byte>(arr), WebSocketMessageType.Text, true, m_cancel_token);
            send_task.Wait();

            while (true)
            {
                byte[] recv_arr = new byte[100 * 1024];
                var recv_task = m_wsock.ReceiveAsync(new ArraySegment<byte>(recv_arr), m_cancel_token);
                WebSocketReceiveResult res = recv_task.Result;
                byte[] data_arr = new byte[res.Count];
                Array.Copy(recv_arr, data_arr, res.Count);
                string recv_str = System.Text.Encoding.Default.GetString(data_arr);
                var recv_obj = (JObject)JsonConvert.DeserializeObject(recv_str);
                uint recv_msg_id = (uint)recv_obj.Property("msg_id");

                if (recv_msg_id == m_cur_msg_id)
                {
                    if(recv_obj.Property("err_code") == null)
                    {
                        Console.WriteLine("login ok");
                    }
                    else
                    {
                        Console.WriteLine("login failed");
                    }
                    break;
                }
            }           
           
            Console.WriteLine("askcoin connector started.");

            DepositList dl = ListDeposits("234");

            //string txid = SendTo("12", 100);
            //Console.WriteLine("txid: {0}", txid);

            Console.Read();
        }
    }
}
