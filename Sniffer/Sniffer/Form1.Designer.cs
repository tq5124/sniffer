﻿namespace Sniffer
{
    partial class Form1
    {
        /// <summary>
        /// 必需的设计器变量。
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// 清理所有正在使用的资源。
        /// </summary>
        /// <param name="disposing">如果应释放托管资源，为 true；否则为 false。</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows 窗体设计器生成的代码

        /// <summary>
        /// 设计器支持所需的方法 - 不要
        /// 使用代码编辑器修改此方法的内容。
        /// </summary>
        private void InitializeComponent()
        {
            this.comboBox1 = new System.Windows.Forms.ComboBox();
            this.button1 = new System.Windows.Forms.Button();
            this.button2 = new System.Windows.Forms.Button();
            this.button3 = new System.Windows.Forms.Button();
            this.button4 = new System.Windows.Forms.Button();
            this.button5 = new System.Windows.Forms.Button();
            this.button6 = new System.Windows.Forms.Button();
            this.button7 = new System.Windows.Forms.Button();
            this.button8 = new System.Windows.Forms.Button();
            this.label1 = new System.Windows.Forms.Label();
            this.dataGridView1 = new System.Windows.Forms.DataGridView();
            this.Column1 = new System.Windows.Forms.DataGridViewTextBoxColumn();
            this.Column2 = new System.Windows.Forms.DataGridViewTextBoxColumn();
            this.Column3 = new System.Windows.Forms.DataGridViewTextBoxColumn();
            this.Column4 = new System.Windows.Forms.DataGridViewTextBoxColumn();
            this.Column5 = new System.Windows.Forms.DataGridViewTextBoxColumn();
            this.Column6 = new System.Windows.Forms.DataGridViewTextBoxColumn();
            this.treeView1 = new System.Windows.Forms.TreeView();
            this.tab_multi = new System.Windows.Forms.TabControl();
            this.tabPage1 = new System.Windows.Forms.TabPage();
            this.filter_rule = new System.Windows.Forms.DataGridView();
            this.filter_rule_key = new System.Windows.Forms.DataGridViewTextBoxColumn();
            this.filter_rule_oper = new System.Windows.Forms.DataGridViewTextBoxColumn();
            this.filter_rule_value = new System.Windows.Forms.DataGridViewTextBoxColumn();
            this.filter_oper = new System.Windows.Forms.ComboBox();
            this.filter_btn_apply = new System.Windows.Forms.Button();
            this.filter_btn_clear = new System.Windows.Forms.Button();
            this.filter_value = new System.Windows.Forms.TextBox();
            this.filter_key = new System.Windows.Forms.ComboBox();
            this.tabPage2 = new System.Windows.Forms.TabPage();
            ((System.ComponentModel.ISupportInitialize)(this.dataGridView1)).BeginInit();
            this.tab_multi.SuspendLayout();
            this.tabPage1.SuspendLayout();
            ((System.ComponentModel.ISupportInitialize)(this.filter_rule)).BeginInit();
            this.SuspendLayout();
            // 
            // comboBox1
            // 
            this.comboBox1.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.comboBox1.FormattingEnabled = true;
            this.comboBox1.Location = new System.Drawing.Point(139, 11);
            this.comboBox1.Name = "comboBox1";
            this.comboBox1.Size = new System.Drawing.Size(380, 20);
            this.comboBox1.TabIndex = 0;
            // 
            // button1
            // 
            this.button1.Location = new System.Drawing.Point(525, 9);
            this.button1.Name = "button1";
            this.button1.Size = new System.Drawing.Size(75, 23);
            this.button1.TabIndex = 1;
            this.button1.Text = "开始抓包";
            this.button1.UseVisualStyleBackColor = true;
            this.button1.Click += new System.EventHandler(this.button1_Click);
            // 
            // button2
            // 
            this.button2.Location = new System.Drawing.Point(525, 38);
            this.button2.Name = "button2";
            this.button2.Size = new System.Drawing.Size(75, 23);
            this.button2.TabIndex = 1;
            this.button2.Text = "停止抓包";
            this.button2.UseVisualStyleBackColor = true;
            this.button2.Click += new System.EventHandler(this.button2_Click);
            // 
            // button3
            // 
            this.button3.Location = new System.Drawing.Point(525, 67);
            this.button3.Name = "button3";
            this.button3.Size = new System.Drawing.Size(75, 23);
            this.button3.TabIndex = 1;
            this.button3.Text = "过滤包";
            this.button3.UseVisualStyleBackColor = true;
            // 
            // button4
            // 
            this.button4.Location = new System.Drawing.Point(525, 96);
            this.button4.Name = "button4";
            this.button4.Size = new System.Drawing.Size(75, 23);
            this.button4.TabIndex = 1;
            this.button4.Text = "搜索";
            this.button4.UseVisualStyleBackColor = true;
            // 
            // button5
            // 
            this.button5.Location = new System.Drawing.Point(525, 125);
            this.button5.Name = "button5";
            this.button5.Size = new System.Drawing.Size(75, 23);
            this.button5.TabIndex = 1;
            this.button5.Text = "查看日志";
            this.button5.UseVisualStyleBackColor = true;
            // 
            // button6
            // 
            this.button6.Location = new System.Drawing.Point(525, 154);
            this.button6.Name = "button6";
            this.button6.Size = new System.Drawing.Size(75, 23);
            this.button6.TabIndex = 1;
            this.button6.Text = "报文重组";
            this.button6.UseVisualStyleBackColor = true;
            // 
            // button7
            // 
            this.button7.Location = new System.Drawing.Point(525, 285);
            this.button7.Name = "button7";
            this.button7.Size = new System.Drawing.Size(75, 23);
            this.button7.TabIndex = 1;
            this.button7.Text = "退出";
            this.button7.UseVisualStyleBackColor = true;
            this.button7.Click += new System.EventHandler(this.button7_Click);
            // 
            // button8
            // 
            this.button8.Location = new System.Drawing.Point(525, 256);
            this.button8.Name = "button8";
            this.button8.Size = new System.Drawing.Size(75, 23);
            this.button8.TabIndex = 1;
            this.button8.Text = "保存TXT";
            this.button8.UseVisualStyleBackColor = true;
            // 
            // label1
            // 
            this.label1.AutoSize = true;
            this.label1.Location = new System.Drawing.Point(40, 14);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(53, 12);
            this.label1.TabIndex = 2;
            this.label1.Text = "选择网卡";
            // 
            // dataGridView1
            // 
            this.dataGridView1.AllowUserToAddRows = false;
            this.dataGridView1.ColumnHeadersHeightSizeMode = System.Windows.Forms.DataGridViewColumnHeadersHeightSizeMode.AutoSize;
            this.dataGridView1.Columns.AddRange(new System.Windows.Forms.DataGridViewColumn[] {
            this.Column1,
            this.Column2,
            this.Column3,
            this.Column4,
            this.Column5,
            this.Column6});
            this.dataGridView1.Location = new System.Drawing.Point(42, 67);
            this.dataGridView1.Name = "dataGridView1";
            this.dataGridView1.RowHeadersVisible = false;
            this.dataGridView1.RowTemplate.Height = 23;
            this.dataGridView1.SelectionMode = System.Windows.Forms.DataGridViewSelectionMode.FullRowSelect;
            this.dataGridView1.Size = new System.Drawing.Size(477, 150);
            this.dataGridView1.TabIndex = 3;
            this.dataGridView1.Click += new System.EventHandler(this.dataGridView_row_click);
            // 
            // Column1
            // 
            this.Column1.HeaderText = "时间";
            this.Column1.Name = "Column1";
            // 
            // Column2
            // 
            this.Column2.HeaderText = "源地址";
            this.Column2.Name = "Column2";
            // 
            // Column3
            // 
            this.Column3.HeaderText = "目的地址";
            this.Column3.Name = "Column3";
            // 
            // Column4
            // 
            this.Column4.HeaderText = "协议";
            this.Column4.Name = "Column4";
            this.Column4.Width = 74;
            // 
            // Column5
            // 
            this.Column5.HeaderText = "信息";
            this.Column5.Name = "Column5";
            // 
            // Column6
            // 
            this.Column6.HeaderText = "index";
            this.Column6.Name = "Column6";
            this.Column6.Visible = false;
            // 
            // treeView1
            // 
            this.treeView1.Location = new System.Drawing.Point(42, 256);
            this.treeView1.Name = "treeView1";
            this.treeView1.Size = new System.Drawing.Size(477, 97);
            this.treeView1.TabIndex = 4;
            // 
            // tab_multi
            // 
            this.tab_multi.Controls.Add(this.tabPage1);
            this.tab_multi.Controls.Add(this.tabPage2);
            this.tab_multi.Location = new System.Drawing.Point(620, 9);
            this.tab_multi.Name = "tab_multi";
            this.tab_multi.SelectedIndex = 0;
            this.tab_multi.Size = new System.Drawing.Size(324, 390);
            this.tab_multi.TabIndex = 6;
            // 
            // tabPage1
            // 
            this.tabPage1.Controls.Add(this.filter_rule);
            this.tabPage1.Controls.Add(this.filter_oper);
            this.tabPage1.Controls.Add(this.filter_btn_apply);
            this.tabPage1.Controls.Add(this.filter_btn_clear);
            this.tabPage1.Controls.Add(this.filter_value);
            this.tabPage1.Controls.Add(this.filter_key);
            this.tabPage1.Location = new System.Drawing.Point(4, 22);
            this.tabPage1.Name = "tabPage1";
            this.tabPage1.Padding = new System.Windows.Forms.Padding(3);
            this.tabPage1.Size = new System.Drawing.Size(316, 364);
            this.tabPage1.TabIndex = 0;
            this.tabPage1.Text = "过滤规则";
            this.tabPage1.UseVisualStyleBackColor = true;
            // 
            // filter_rule
            // 
            this.filter_rule.AllowUserToAddRows = false;
            this.filter_rule.BackgroundColor = System.Drawing.SystemColors.ButtonHighlight;
            this.filter_rule.BorderStyle = System.Windows.Forms.BorderStyle.None;
            this.filter_rule.ColumnHeadersHeightSizeMode = System.Windows.Forms.DataGridViewColumnHeadersHeightSizeMode.AutoSize;
            this.filter_rule.Columns.AddRange(new System.Windows.Forms.DataGridViewColumn[] {
            this.filter_rule_key,
            this.filter_rule_oper,
            this.filter_rule_value});
            this.filter_rule.Location = new System.Drawing.Point(6, 65);
            this.filter_rule.Name = "filter_rule";
            this.filter_rule.RowHeadersVisible = false;
            this.filter_rule.RowTemplate.Height = 23;
            this.filter_rule.ScrollBars = System.Windows.Forms.ScrollBars.Vertical;
            this.filter_rule.SelectionMode = System.Windows.Forms.DataGridViewSelectionMode.FullRowSelect;
            this.filter_rule.Size = new System.Drawing.Size(293, 277);
            this.filter_rule.TabIndex = 9;
            // 
            // filter_rule_key
            // 
            this.filter_rule_key.HeaderText = "键";
            this.filter_rule_key.Name = "filter_rule_key";
            // 
            // filter_rule_oper
            // 
            this.filter_rule_oper.HeaderText = "操作符";
            this.filter_rule_oper.Name = "filter_rule_oper";
            this.filter_rule_oper.Width = 80;
            // 
            // filter_rule_value
            // 
            this.filter_rule_value.HeaderText = "值";
            this.filter_rule_value.Name = "filter_rule_value";
            // 
            // filter_oper
            // 
            this.filter_oper.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.filter_oper.FormattingEnabled = true;
            this.filter_oper.Items.AddRange(new object[] {
            "==",
            "!=",
            "包含"});
            this.filter_oper.Location = new System.Drawing.Point(125, 10);
            this.filter_oper.Name = "filter_oper";
            this.filter_oper.Size = new System.Drawing.Size(68, 20);
            this.filter_oper.TabIndex = 8;
            // 
            // filter_btn_apply
            // 
            this.filter_btn_apply.Location = new System.Drawing.Point(6, 36);
            this.filter_btn_apply.Name = "filter_btn_apply";
            this.filter_btn_apply.Size = new System.Drawing.Size(75, 23);
            this.filter_btn_apply.TabIndex = 6;
            this.filter_btn_apply.Text = "apply";
            this.filter_btn_apply.UseVisualStyleBackColor = true;
            this.filter_btn_apply.Click += new System.EventHandler(this.filter_btn_apply_Click);
            // 
            // filter_btn_clear
            // 
            this.filter_btn_clear.Location = new System.Drawing.Point(87, 36);
            this.filter_btn_clear.Name = "filter_btn_clear";
            this.filter_btn_clear.Size = new System.Drawing.Size(75, 23);
            this.filter_btn_clear.TabIndex = 5;
            this.filter_btn_clear.Text = "clear";
            this.filter_btn_clear.UseVisualStyleBackColor = true;
            this.filter_btn_clear.Click += new System.EventHandler(this.filter_btn_clear_Click);
            // 
            // filter_value
            // 
            this.filter_value.Location = new System.Drawing.Point(199, 10);
            this.filter_value.Name = "filter_value";
            this.filter_value.Size = new System.Drawing.Size(100, 21);
            this.filter_value.TabIndex = 4;
            // 
            // filter_key
            // 
            this.filter_key.DisplayMember = "ip";
            this.filter_key.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.filter_key.FormattingEnabled = true;
            this.filter_key.Items.AddRange(new object[] {
            "ip_addr",
            "ip_version",
            "port",
            "protocol",
            "DF",
            "MF"});
            this.filter_key.Location = new System.Drawing.Point(6, 10);
            this.filter_key.Name = "filter_key";
            this.filter_key.Size = new System.Drawing.Size(112, 20);
            this.filter_key.TabIndex = 2;
            // 
            // tabPage2
            // 
            this.tabPage2.Location = new System.Drawing.Point(4, 22);
            this.tabPage2.Name = "tabPage2";
            this.tabPage2.Padding = new System.Windows.Forms.Padding(3);
            this.tabPage2.Size = new System.Drawing.Size(316, 364);
            this.tabPage2.TabIndex = 1;
            this.tabPage2.Text = "tabPage2";
            this.tabPage2.UseVisualStyleBackColor = true;
            // 
            // Form1
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 12F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(956, 411);
            this.Controls.Add(this.tab_multi);
            this.Controls.Add(this.treeView1);
            this.Controls.Add(this.dataGridView1);
            this.Controls.Add(this.label1);
            this.Controls.Add(this.button8);
            this.Controls.Add(this.button7);
            this.Controls.Add(this.button6);
            this.Controls.Add(this.button5);
            this.Controls.Add(this.button4);
            this.Controls.Add(this.button3);
            this.Controls.Add(this.button2);
            this.Controls.Add(this.button1);
            this.Controls.Add(this.comboBox1);
            this.Name = "Form1";
            this.Text = "Sniffer";
            this.Load += new System.EventHandler(this.Form1_Load);
            ((System.ComponentModel.ISupportInitialize)(this.dataGridView1)).EndInit();
            this.tab_multi.ResumeLayout(false);
            this.tabPage1.ResumeLayout(false);
            this.tabPage1.PerformLayout();
            ((System.ComponentModel.ISupportInitialize)(this.filter_rule)).EndInit();
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.ComboBox comboBox1;
        private System.Windows.Forms.Button button1;
        private System.Windows.Forms.Button button2;
        private System.Windows.Forms.Button button3;
        private System.Windows.Forms.Button button4;
        private System.Windows.Forms.Button button5;
        private System.Windows.Forms.Button button6;
        private System.Windows.Forms.Button button7;
        private System.Windows.Forms.Button button8;
        private System.Windows.Forms.Label label1;
        private System.Windows.Forms.DataGridView dataGridView1;
        private System.Windows.Forms.DataGridViewTextBoxColumn Column1;
        private System.Windows.Forms.DataGridViewTextBoxColumn Column2;
        private System.Windows.Forms.DataGridViewTextBoxColumn Column3;
        private System.Windows.Forms.DataGridViewTextBoxColumn Column4;
        private System.Windows.Forms.DataGridViewTextBoxColumn Column5;
        private System.Windows.Forms.DataGridViewTextBoxColumn Column6;
        private System.Windows.Forms.TreeView treeView1;
        private System.Windows.Forms.TabControl tab_multi;
        private System.Windows.Forms.TabPage tabPage1;
        private System.Windows.Forms.Button filter_btn_apply;
        private System.Windows.Forms.Button filter_btn_clear;
        private System.Windows.Forms.TextBox filter_value;
        private System.Windows.Forms.ComboBox filter_key;
        private System.Windows.Forms.TabPage tabPage2;
        private System.Windows.Forms.ComboBox filter_oper;
        private System.Windows.Forms.DataGridView filter_rule;
        private System.Windows.Forms.DataGridViewTextBoxColumn filter_rule_key;
        private System.Windows.Forms.DataGridViewTextBoxColumn filter_rule_oper;
        private System.Windows.Forms.DataGridViewTextBoxColumn filter_rule_value;
    }
}

