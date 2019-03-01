using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Market.CurrencyManager.ConnectorApi;
using Askcoin;

namespace Askcoin
{
    class Program
    {
        static void Main(string[] args)
        {
            AskcoinConnector askcoin_connetor = new AskcoinConnector();
            askcoin_connetor.Main();
        }
    }
}
