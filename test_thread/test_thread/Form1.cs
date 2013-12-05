using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Windows.Forms;
using System.Threading;

namespace test_thread
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }

        private   delegate   void setTextDelegate( int value);   //先声明一个传递int类型参数，并返回为void的委托

        private void button1_Click(object sender, EventArgs e)
　       {
　　          Thread newThread = new Thread(new ThreadStart(threadHandler));
              newThread.Start();
　       }

        private void threadHandler()
        {

            for(int i =0 ; i <=100 ;  i ++)
            {
                    this.UIHandler(i);

                    Thread.Sleep(100);

            }
        }

        private void UIHandler(int value)
            {

            if(this.label1.InvokeRequired)  //判断label1控件是否是调用线程(即newThread线程)创建的,也就是是否跨线程调用,如果是则返回true,否则返回false
            {
                this.label1.BeginInvoke(new setTextDelegate(setLabelText),new object []{ value});  //异步调用setLabelText方法，并传递一个int参数
            }
            else
            {
                this.label1.Text = value.ToString() + "%";
            }
            }

            private void setLabelText(int value)  //当跨线程调用时，调用该方法进行UI界面更新
            {
            this.label1.Text = value.ToString() + "%";
            }
    }
}
