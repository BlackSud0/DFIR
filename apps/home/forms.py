# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SelectField, BooleanField, SubmitField
from wtforms.validators import DataRequired, Optional

# Create Case Form

class CreateCaseForm(FlaskForm):
    case_name = StringField('Case name', validators=[DataRequired()])
    assigned_to = StringField('Analyst Name', validators=[DataRequired()])
    ticket_id = StringField('Optional', validators=[Optional()])
    description = TextAreaField('Case description', validators=[Optional()])
    case_priority = SelectField('Select Priority',
                        choices=[('', 'Select Priority'),
                                 ('1', 'Critical'),
                                 ('2', 'Hard'),
                                 ('3', 'Medium'),
                                 ('4', 'Low')],
                        validators=[DataRequired()])
    virustotal = BooleanField("VirusTotal", validators=[DataRequired()])
    anyrun = BooleanField("AnyRun", validators=[Optional()])
    hybridanalysis = BooleanField("Hybrid Analysis", validators=[Optional()])
    alienvault_otx = BooleanField("AlienVault OTX", validators=[Optional()])
    urlscan = BooleanField("URLHaus & URLScan", validators=[Optional()])
    submit = SubmitField("Create Now")
