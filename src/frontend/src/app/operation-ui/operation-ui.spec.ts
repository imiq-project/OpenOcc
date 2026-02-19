import { ComponentFixture, TestBed } from '@angular/core/testing';

import { OperationUi } from './operation-ui';

describe('OperationUi', () => {
  let component: OperationUi;
  let fixture: ComponentFixture<OperationUi>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [OperationUi]
    })
    .compileComponents();

    fixture = TestBed.createComponent(OperationUi);
    component = fixture.componentInstance;
    await fixture.whenStable();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
