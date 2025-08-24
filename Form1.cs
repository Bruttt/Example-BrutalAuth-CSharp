using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using BrutalAuth;

namespace Example_BrutalAuth
{
    public partial class Login : Form
    {
        private readonly BAuth BrutalAuth;
        public Login()
        {
            InitializeComponent();
            string appId = "your_app_id";
            string host = "api.brutalauth.site";

            BrutalAuth = new BAuth(appId, host);
            this.AcceptButton = guna2Button1;
        }

        private void guna2TextBox3_TextChanged(object sender, EventArgs e)
        {

        }



        private void guna2Button1_Click(object sender, EventArgs e) // LOGIN
        {
            var ok = BrutalAuth.LoginUser(username.Text, passwords.Text);
            if (ok)
            {
                MessageBox.Show("Login Sucess. Check your credentials.");
                Form2 f2 = new Form2();
                this.Hide();
                f2.Show();
               
            }
            else
            {
                MessageBox.Show("Login failed. Check your credentials.");
            }
        }

        private void guna2Button2_Click(object sender, EventArgs e) // REGISTER
        {
            var ok = BrutalAuth.RegisterUser(license.Text, username.Text, passwords.Text);
            if (ok)
            {
                MessageBox.Show("Registration Sucess. You can login now");

            }
            else
            {
                MessageBox.Show("Registration failed. Check license or server.");
            }
        }

        private void Login_Load(object sender, EventArgs e)
        {

        }
    }
}
