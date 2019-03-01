using System.Collections.Generic;

namespace Market.CurrencyManager.ConnectorApi
{
    public class Withdraw
    {
        public string Address;
        public decimal Amount;
        public string TxId;
        public int Confirmations;
        public bool Confirmed;
        public decimal WithdrawFee;
    }

    public class WithdrawList
    {
        public List<Withdraw> Withdraws;
        public string BatchId;
    }
}
