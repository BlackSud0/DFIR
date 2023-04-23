# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

from apps import db

from apps.home import blueprint
from flask import request, render_template, redirect, url_for, abort
from flask_login import login_required, current_user
from jinja2 import TemplateNotFound
from apps.authentication.models import Cases, APIs
from apps.home.forms import CreateCaseForm, CreateSettingsForm


@blueprint.route('/index')
@login_required
def index():
    cases_count = Cases.query.count()
    return render_template('home/index.html', cases_count=cases_count, segment='index')


@blueprint.route('/<template>')
@login_required
def route_template(template):

    try:

        if not template.endswith('.html'):
            template += '.html'

        # Detect the current page
        segment = get_segment(request)

        # Serve the file (if exists) from app/templates/home/FILE.html
        return render_template("home/" + template, segment=segment)

    except TemplateNotFound:
        return render_template('home/page-404.html'), 404

    except:
        return render_template('home/page-500.html'), 500

@blueprint.route('/newcase', methods=['GET', 'POST'])
@login_required
def newcase():
    create_case_form = CreateCaseForm(request.form)
    if request.method == "POST":

        case_name = request.form.get('case_name')
        # Check casename exists
        case = Cases.query.filter_by(case_name=case_name).first()
        if case:
            return render_template('home/newcase.html',
                                   msg='That Case name already exists',
                                   success=False,
                                   form=create_case_form)
        
        # else we can create the case
        case = Cases(case_name=case_name,user_id=current_user.get_id())
        case.assigned_to = request.form.get('assigned_to')
        case.ticket_id = request.form.get('ticket_id')
        case.case_priority = request.form.get('case_priority')
        case.description = request.form.get('description')
        # Anti-Malware Engines
        case.virustotal = True if request.form.get('virustotal') == "y" else False
        case.anyrun = True if request.form.get('anyrun') == "y" else False
        case.hybridanalysis = True if request.form.get('hybridanalysis') == "y" else False
        case.malwarebazaar = True if request.form.get('malwarebazaar') == "y" else False
        case.alienvault_otx = True if request.form.get('alienvault_otx') == "y" else False
        case.urlscan = True if request.form.get('urlscan') == "y" else False

        db.session.add(case)
        db.session.commit()
        return redirect(url_for('home_blueprint.cases',case_id=case.id))

    else:
        return render_template('home/newcase.html', form=create_case_form)

@blueprint.route('/cases/<int:case_id>')
@login_required
def cases(case_id):
    case = Cases.query.filter_by(id=case_id).first_or_404()
    return render_template("home/case.html", case=case)

@blueprint.route('/allcases')
@login_required
def allcases():
    allcases = (
        Cases.query.filter_by(user_id=current_user.get_id())
        .order_by(Cases.id.desc())
        .paginate(per_page=50)
    )
    return render_template("home/allcases.html", cases=allcases)

@blueprint.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    Old_API = APIs.query.filter_by(user_id=current_user.get_id()).first()
    create_settings_form = CreateSettingsForm(request.form)
    if request.method == "POST":

        # Check API exists
        if Old_API:
            Old_API.VTAPI = request.form.get('VTAPI')
            Old_API.HBAPI = request.form.get('HBAPI')
            Old_API.MBAPI = request.form.get('MBAPI')
            Old_API.ARAPI = request.form.get('ARAPI')
            Old_API.URLAPI = request.form.get('URLAPI')
            Old_API.OTXAPI = request.form.get('OTXAPI')

            db.session.add(Old_API)
            db.session.commit()
            return render_template('home/settings.html',
                                   msg='Settings updated successfully',
                                   form=create_settings_form,
                                   API=Old_API)
        
        API = APIs(user_id=current_user.get_id())
        # Anti-Malware API
        API.VTAPI = request.form.get('VTAPI')
        API.HBAPI = request.form.get('HBAPI')
        API.MBAPI = request.form.get('MBAPI')
        API.ARAPI = request.form.get('ARAPI')
        API.URLAPI = request.form.get('URLAPI')
        API.OTXAPI = request.form.get('OTXAPI')

        db.session.add(API)
        db.session.commit()
        return render_template('home/settings.html',
                                   msg='Settings updated successfully',
                                   form=create_settings_form,
                                   API=API)

    else:
        return render_template('home/settings.html', form=create_settings_form, API=Old_API)

# Helper - Extract current page name from request
def get_segment(request):

    try:

        segment = request.path.split('/')[-1]

        if segment == '':
            segment = 'index'

        return segment

    except:
        return None
