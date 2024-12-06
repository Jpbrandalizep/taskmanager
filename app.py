import csv
import pytz
import io
import pandas as pd
from flask import Response
from flask import Flask, request, render_template, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps


# aplicativo Flask e configuração do banco de dados
app = Flask(__name__)
app.config['SECRET_KEY'] = 'sua_chave_secreta'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///task_manager.db'
db = SQLAlchemy(app)

def redirect_if_authenticated(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' in session:
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated_function


# banco de dados
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)


class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    completed = db.Column(db.Boolean, default=False)
    due_date = db.Column(db.DateTime, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    priority = db.Column(db.Boolean, default=False)
    completed_at = db.Column(db.DateTime, nullable=True) 

    def __repr__(self):
        return f'<Task {self.title}>'


# página inicial
import pytz
from datetime import datetime

from datetime import datetime
import pytz

from datetime import datetime
import pytz

from datetime import datetime
import pytz

@app.route('/')
def home():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])

    # filtros
    filter_completed = request.args.get('filter_completed')
    filter_priority = request.args.get('filter_priority')

    # busca
    tasks_query = Task.query.filter_by(user_id=session['user_id'])

    if filter_completed == '1':
        tasks_query = tasks_query.filter_by(completed=True)
    elif filter_completed == '0':
        tasks_query = tasks_query.filter_by(completed=False)

    if filter_priority == '1':
        tasks_query = tasks_query.filter_by(priority=True)

    tasks = tasks_query.all()

    # cálculo de atraso para cada tarefa
    br_tz = pytz.timezone('America/Sao_Paulo')
    now = datetime.now(br_tz)

    for task in tasks:
        if task.completed_at:
            task.completed_at = task.completed_at.astimezone(br_tz).strftime('%d/%m/%Y %H:%M:%S')

        if task.due_date:
            # fuso horário da data de vencimento
            due_date_obj = task.due_date.astimezone(br_tz)
            task.due_date = due_date_obj.strftime('%d/%m/%Y')
            if due_date_obj < now:
                delay = now - due_date_obj
                delay_days = delay.days
                delay_hours, remainder = divmod(delay.seconds, 3600)
                delay_minutes, delay_seconds = divmod(remainder, 60)
                task.delay_message = f"Esta tarefa está atrasada em {delay_days} dias, {delay_hours} horas e {delay_minutes} minutos."
                task.days_remaining = None 
            else:
                task.days_remaining = (due_date_obj - now).days  
                task.delay_message = None 
        else:
            task.days_remaining = None
            task.delay_message = "Sem prazo definido"

    return render_template('home.html', tasks=tasks, user=user)


# novo usuário
@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session: 
        return redirect(url_for('home'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # se as senhas coincidem
        if password != confirm_password:
            flash('As senhas não coincidem.', 'danger')
            return render_template('register.html')

        # se nome de usuário já existe
        if User.query.filter_by(username=username).first():
            flash('Este nome de usuário já está em uso.', 'danger')
            return render_template('register.html')

        # novo usuário
        hashed_password = generate_password_hash(password, method='sha256')
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        login_url = url_for('login')
        flash(f'Registro realizado com sucesso! <a href="{login_url}">Faça o login!</a>', 'success')
        return render_template('register.html')

    return render_template('register.html')

# Rota para login
@app.route('/login', methods=['GET', 'POST'])
@redirect_if_authenticated
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            return redirect(url_for('home'))
        flash('Usuário ou senha inválidos', 'danger')
    return render_template('login.html')


# adicionar uma nova tarefa
from datetime import datetime
import pytz

@app.route('/add_task', methods=['POST'])
def add_task():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    title = request.form.get('title')
    due_date = request.form.get('due_date')
    priority = request.form.get('priority', 'off') == 'on' 
    if due_date and due_date != '':
        due_date = datetime.strptime(due_date, '%Y-%m-%dT%H:%M')
    else:
        due_date = None
    delay_message = None
    if due_date and due_date < datetime.now():
        delay = datetime.now() - due_date
        delay_days = delay.days
        delay_hours, remainder = divmod(delay.seconds, 3600)
        delay_minutes, delay_seconds = divmod(remainder, 60)
        delay_message = f"Esta tarefa está atrasada em {delay_days} dias, {delay_hours} horas, {delay_minutes} minutos e {delay_seconds} segundos."
    
    # Criar a nova tarefa
    if title:
        new_task = Task(
            title=title,
            due_date=due_date,
            user_id=session['user_id'],
            priority=priority
        )

        db.session.add(new_task)
        db.session.commit()

        flash('Tarefa adicionada com sucesso!' + (f" {delay_message}" if delay_message else ''), 'success')
    else:
        flash('Título da tarefa é obrigatório!', 'danger')

    return redirect(url_for('home'))



@app.route('/revert_task/<int:task_id>', methods=['POST'])
def revert_task(task_id):
    task = Task.query.get(task_id)
    if task and task.user_id == session['user_id']:
        task.completed = False
        task.completed_at = None  # Remover a data de conclusão
        db.session.commit()
        flash('Tarefa revertida para pendente!', 'success')
    return redirect(url_for('home'))



@app.route('/delete_account', methods=['POST'])
def delete_account():
    if 'user_id' in session: 
        user = User.query.get(session['user_id'])
        db.session.delete(user) 
        db.session.commit()
        session.pop('user_id', None) 
        flash('Conta excluída com sucesso!', 'success') 
        return redirect(url_for('login')) 
    return redirect(url_for('login'))



from datetime import datetime

@app.route('/complete_task/<int:task_id>', methods=['POST'])
def complete_task(task_id):
    task = Task.query.get(task_id)
    if task and task.user_id == session['user_id']:
        task.completed = True
        br_tz = pytz.timezone('America/Sao_Paulo')
        task.completed_at = datetime.now(br_tz)
        db.session.commit()
        flash('Tarefa marcada como concluída!', 'success')
    return redirect(url_for('home'))


# excluir uma tarefa
@app.route('/delete_task/<int:task_id>', methods=['POST'])
def delete_task(task_id):
    task = Task.query.get(task_id) 
    if task and task.user_id == session['user_id']:
        db.session.delete(task) 
        db.session.commit() 
        flash('Tarefa excluída com sucesso!', 'success') 
    return redirect(url_for('home'))








# alterar a senha do usuário
@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    
    if request.method == 'POST':
        old_password = request.form['old_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        # verificaçao se a senha antiga está correta
        if not check_password_hash(user.password, old_password):
            flash('Senha atual incorreta ou senha nova não coincide.', 'danger') 
            return render_template('change_password.html')  

        # verificaçao se as senhas novas coincidem
        if new_password != confirm_password:
            flash('Senha atual incorreta ou senha nova não coincide.', 'danger')
            return render_template('change_password.html') 

        # Atualiza a senha do usuário
        user.password = generate_password_hash(new_password, method='sha256')
        db.session.commit()

        flash('Senha alterada com sucesso!', 'success') 
        return render_template('change_password.html')  

    return render_template('change_password.html')  

@app.route('/report', methods=['GET'])
def report():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    
    tasks = Task.query.filter_by(user_id=user.id).all()
    pending_tasks = [task for task in tasks if not task.completed]
    completed_tasks = [task for task in tasks if task.completed]
    overdue_tasks = [task for task in tasks if task.due_date and task.due_date < datetime.now()]
    
    return render_template('report.html',
                           user=user,
                           pending_tasks=pending_tasks,
                           completed_tasks=completed_tasks,
                           overdue_tasks=overdue_tasks)


@app.route('/download_report/<report_type>', methods=['GET'])
def download_report(report_type):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    tasks = Task.query.filter_by(user_id=user.id).all()

    pending_tasks = [task for task in tasks if not task.completed]
    completed_tasks = [task for task in tasks if task.completed]
    overdue_tasks = [task for task in tasks if task.due_date and task.due_date < datetime.now()]

    if report_type == 'csv':
        return generate_csv(user.username, pending_tasks, completed_tasks, overdue_tasks)
    elif report_type == 'txt':
        return generate_txt(user.username, pending_tasks, completed_tasks, overdue_tasks)
    else:
        flash('Tipo de relatório inválido.', 'danger')
        return redirect(url_for('home'))

def generate_csv(username, pending, completed, overdue):
    # lista de tarefas com seus dados
    tasks_data = []

    for task in pending:
        due_date = task.due_date.strftime('%d/%m/%Y') if task.due_date else 'Sem data'
        tasks_data.append([task.id, task.title, "Pendente", due_date])

    for task in completed:
        completed_at = task.completed_at.strftime('%d/%m/%Y %H:%M:%S') if task.completed_at else 'Sem data'
        tasks_data.append([task.id, task.title, "Concluída", completed_at])

    for task in overdue:
        due_date = task.due_date.strftime('%d/%m/%Y') if task.due_date else 'Sem data'
        tasks_data.append([task.id, task.title, "Atrasada", due_date])

    # arquivo CSV na memória
    output = io.StringIO()
    writer = csv.writer(output, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)

    # cabeçalho do CSV
    writer.writerow(["ID", "Título", "Status", "Data de Vencimento"])

    # escrevendo os dados no CSV
    writer.writerows(tasks_data)

    # arquivo CSV com codificação UTF-8
    output.seek(0)  # Volta para o início do arquivo para leitura
    return Response(output, mimetype='text/csv; charset=utf-8', headers={
        "Content-Disposition": f"attachment;filename=relatorio_{username}.csv"
    })

def generate_txt(username, pending, completed, overdue):
    def create_txt():
        yield f"Relatório de Tarefas para {username}\n\n"
        yield "Tarefas Pendentes:\n"
        for task in pending:
            yield f"- {task.title} | Vencimento: {task.due_date}\n"
        yield "\nTarefas Concluídas:\n"
        for task in completed:
            yield f"- {task.title} | Concluída em: {task.completed_at}\n"
        yield "\nTarefas Atrasadas:\n"
        for task in overdue:
            yield f"- {task.title} | Vencimento: {task.due_date}\n"
    
    return Response(create_txt(), mimetype='text/plain', headers={
        "Content-Disposition": f"attachment;filename=relatorio_{username}.txt"
    })


@app.route('/account_settings', methods=['GET'])
def account_settings():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('account_settings.html')

# encerrar a sessão do usuário
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))

# se o banco de dados foi criado e execute o aplicativo
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
