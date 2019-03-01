using System.Collections.Generic;

namespace Market.CurrencyManager.ConnectorApi
{
    public class Deposit
    {
        public string Address;
        public decimal Amount;
        public string TxId;
        public int Confirmations;
        public bool Confirmed;
        public decimal DepositFee;
    }

    public class DepositList
    {
        public List<Deposit> Deposits;
        public string BatchId;
    }
}
