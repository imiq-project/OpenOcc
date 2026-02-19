import { ComponentFixture, TestBed } from '@angular/core/testing';

import { ConfigDialog } from './config-dialog';

describe('ConfigDialog', () => {
  let component: ConfigDialog;
  let fixture: ComponentFixture<ConfigDialog>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [ConfigDialog]
    })
    .compileComponents();

    fixture = TestBed.createComponent(ConfigDialog);
    component = fixture.componentInstance;
    await fixture.whenStable();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
